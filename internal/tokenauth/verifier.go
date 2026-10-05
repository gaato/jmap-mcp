// Package tokenauth validates OAuth 2.1 access tokens issued by the
// authorization server (Kanidm) for this resource server.
//
// Kanidm issues RFC 9068 JWT access tokens (typ "at+jwt", ES256 by default)
// whose aud is the OAuth2 client name and whose sub is the account UUID.
// The token is never forwarded anywhere except to the optional introspection
// endpoint of the same authorization server.
package tokenauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gaato/jmap-mcp/internal/logsafe"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Options configures a Verifier.
type Options struct {
	Issuer   string // exact expected iss
	Audience string // must be contained in aud; client_id must equal it too
	JWKSURL  string
	// AllowedSubject is the single user allowed to use this server, compared
	// exactly with the sub claim (Kanidm: the account UUID).
	AllowedSubject string
	// IntrospectionURL, if set, is called (RFC 7662, no client auth, as Kanidm
	// allows) to detect revoked sessions. Positive results are cached for
	// IntrospectionCacheTTL (at most a minute).
	IntrospectionURL string

	Leeway time.Duration
	// HTTPClient is used for JWKS and introspection. Redirects are never
	// followed, so the token cannot be forwarded elsewhere.
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time

	// JWKSMaxAge is when a fetched JWKS should be refreshed (soft expiry).
	JWKSMaxAge time.Duration
	// JWKSGrace is how long after JWKSMaxAge cached keys stay usable while
	// refreshing fails; after that verification fails closed.
	JWKSGrace time.Duration
	// JWKSMinRefreshInterval rate-limits refetches (unknown kids, outages).
	JWKSMinRefreshInterval time.Duration
	// JWKSFetchTimeout bounds one JWKS fetch.
	JWKSFetchTimeout time.Duration
	// IntrospectionCacheTTL bounds how long a positive introspection result
	// is reused; values above MaxIntrospectionCacheTTL are clamped.
	IntrospectionCacheTTL time.Duration
}

// MaxIntrospectionCacheTTL bounds how late a revoked session is noticed.
const MaxIntrospectionCacheTTL = time.Minute

// Verifier implements auth.TokenVerifier.
type Verifier struct {
	opts   Options
	jwks   *jwksCache
	parser *jwt.Parser
	log    *slog.Logger

	intro *introspector
}

// DefaultLeeway is the clock skew tolerated for exp/nbf/iat.
const DefaultLeeway = 30 * time.Second

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// New returns a Verifier. Zero-valued tuning options get sensible defaults.
func New(o Options) *Verifier {
	if o.Leeway == 0 {
		o.Leeway = DefaultLeeway
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	hc := *o.HTTPClient
	hc.CheckRedirect = noRedirects
	o.HTTPClient = &hc
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.JWKSMaxAge == 0 {
		o.JWKSMaxAge = time.Hour
	}
	if o.JWKSGrace == 0 {
		o.JWKSGrace = 10 * time.Minute
	}
	if o.JWKSMinRefreshInterval == 0 {
		o.JWKSMinRefreshInterval = 30 * time.Second
	}
	if o.JWKSFetchTimeout == 0 {
		o.JWKSFetchTimeout = 10 * time.Second
	}
	if o.IntrospectionCacheTTL <= 0 || o.IntrospectionCacheTTL > MaxIntrospectionCacheTTL {
		o.IntrospectionCacheTTL = MaxIntrospectionCacheTTL
	}
	return &Verifier{
		opts: o,
		jwks: &jwksCache{
			url:          o.JWKSURL,
			client:       o.HTTPClient,
			now:          o.Now,
			softMaxAge:   o.JWKSMaxAge,
			grace:        o.JWKSGrace,
			minInterval:  o.JWKSMinRefreshInterval,
			fetchTimeout: o.JWKSFetchTimeout,
			log:          o.Logger,
		},
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"ES256", "RS256"}),
			jwt.WithIssuer(o.Issuer),
			jwt.WithAudience(o.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(o.Leeway),
			jwt.WithTimeFunc(o.Now),
		),
		log: o.Logger,
		intro: &introspector{
			url:         o.IntrospectionURL,
			client:      o.HTTPClient,
			now:         o.Now,
			positiveTTL: o.IntrospectionCacheTTL,
			negativeTTL: NegativeIntrospectionCacheTTL,
			timeout:     o.JWKSFetchTimeout,
			maxEntries:  introspectionCacheSize,
			cache:       make(map[[32]byte]introEntry),
		},
	}
}

// errUnavailable is returned (and surfaces as HTTP 503, see Middleware) when the token could
// not be checked because a dependency failed. It deliberately carries no detail.
var errUnavailable = errors.New("token verification unavailable")

// Verify is an auth.TokenVerifier. Rejections unwrap to auth.ErrInvalidToken
// and carry no detail for the client; the reason is logged instead.
// Scope enforcement (403) is left to auth.RequireBearerToken via TokenInfo.Scopes.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	info, reason, err := v.verify(ctx, token)
	if err != nil {
		attrs := logsafe.Attrs(err)
		if errors.Is(err, errNoValidKeys) {
			attrs = append(attrs, "detail", "no valid signing keys")
		}
		v.log.ErrorContext(ctx, "token verification failed", attrs...)
		return nil, errUnavailable
	}
	if reason != "" {
		v.log.WarnContext(ctx, "token rejected", "reason", reason)
		return nil, auth.ErrInvalidToken
	}
	return info, nil
}

func (v *Verifier) verify(ctx context.Context, token string) (_ *auth.TokenInfo, reason string, _ error) {
	var keyErr error
	claims := jwt.MapClaims{}
	tok, err := v.parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		k, err := v.jwks.lookup(ctx, kid)
		if err != nil {
			if !errors.Is(err, errUnknownKID) {
				keyErr = err
			}
			return nil, err
		}
		if alg, _ := t.Header["alg"].(string); alg != k.alg {
			return nil, errAlgMismatch
		}
		return k.key, nil
	})
	if keyErr != nil {
		return nil, "", logsafe.Wrap("jwks", keyErr)
	}
	if err != nil {
		return nil, parseReason(err), nil
	}

	// RFC 9068 section 4: the typ header must be at+jwt (optionally with the
	// application/ prefix). This rejects ID tokens signed with the same key.
	typ, _ := tok.Header["typ"].(string)
	if t := strings.ToLower(typ); t != "at+jwt" && t != "application/at+jwt" {
		return nil, "typ is not at+jwt", nil
	}

	// RFC 9068 section 2.2 required claims (iss, aud, exp are checked by
	// the parser; nbf is optional).
	subject, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	jti, _ := claims["jti"].(string)
	iat, err := claims.GetIssuedAt()
	switch {
	case subject == "":
		return nil, "sub missing", nil
	case clientID == "":
		return nil, "client_id missing", nil
	case jti == "":
		return nil, "jti missing", nil
	case err != nil || iat == nil:
		return nil, "iat missing", nil
	}
	// Kanidm sets client_id to the client name, which is also the audience.
	if clientID != v.opts.Audience {
		return nil, "client_id does not match audience", nil
	}
	if subject != v.opts.AllowedSubject {
		return nil, "subject not allowed", nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, "bad exp", nil
	}

	scopeStr, _ := claims["scope"].(string)

	if v.opts.IntrospectionURL != "" {
		active, err := v.intro.check(ctx, token, exp.Time)
		if err != nil {
			return nil, "", err
		}
		if !active {
			return nil, "token inactive at introspection", nil
		}
	}

	return &auth.TokenInfo{
		Scopes:     strings.Fields(scopeStr),
		Expiration: exp.Time,
		UserID:     subject,
	}, "", nil
}

var errAlgMismatch = errors.New("alg does not match key")

// parseReason maps a parse/validation error to a fixed string, so that no
// token-supplied text ends up in the logs.
func parseReason(err error) string {
	for _, r := range []struct {
		err    error
		reason string
	}{
		{errUnknownKID, "unknown kid"},
		{errAlgMismatch, "alg does not match key"},
		{jwt.ErrTokenMalformed, "malformed"},
		{jwt.ErrTokenSignatureInvalid, "bad signature"},
		{jwt.ErrTokenExpired, "expired"},
		{jwt.ErrTokenNotValidYet, "not valid yet"},
		{jwt.ErrTokenUsedBeforeIssued, "used before issued"},
		{jwt.ErrTokenInvalidIssuer, "wrong issuer"},
		{jwt.ErrTokenInvalidAudience, "wrong audience"},
		{jwt.ErrTokenRequiredClaimMissing, "required claim missing"},
		{jwt.ErrTokenInvalidClaims, "invalid claims"},
		{jwt.ErrTokenUnverifiable, "unverifiable"},
	} {
		if errors.Is(err, r.err) {
			return r.reason
		}
	}
	return "invalid token"
}
