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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Options configures a Verifier.
type Options struct {
	Issuer         string // exact expected iss
	Audience       string // must be contained in aud
	JWKSURL        string
	SubjectClaim   string // claim holding the user identity, normally "sub"
	AllowedSubject string // the single user allowed to use this server
	// IntrospectionURL, if set, is called (RFC 7662, no client auth, as Kanidm
	// allows) to detect revoked sessions. Results are cached briefly.
	IntrospectionURL string

	Leeway     time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time

	// JWKSMaxAge bounds how long a fetched JWKS is trusted without refetching.
	JWKSMaxAge time.Duration
	// JWKSMinRefreshInterval rate-limits refetches caused by unknown kids.
	JWKSMinRefreshInterval time.Duration
	// IntrospectionCacheTTL bounds how long a positive introspection result is reused.
	IntrospectionCacheTTL time.Duration
}

// Verifier implements auth.TokenVerifier.
type Verifier struct {
	opts   Options
	jwks   *jwksCache
	parser *jwt.Parser
	log    *slog.Logger

	introMu    sync.Mutex
	introCache map[string]time.Time // jti -> cached until
}

// DefaultLeeway is the clock skew tolerated for exp/nbf/iat.
const DefaultLeeway = 30 * time.Second

// New returns a Verifier. Zero-valued tuning options get sensible defaults.
func New(o Options) *Verifier {
	if o.SubjectClaim == "" {
		o.SubjectClaim = "sub"
	}
	if o.Leeway == 0 {
		o.Leeway = DefaultLeeway
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.JWKSMaxAge == 0 {
		o.JWKSMaxAge = time.Hour
	}
	if o.JWKSMinRefreshInterval == 0 {
		o.JWKSMinRefreshInterval = 30 * time.Second
	}
	if o.IntrospectionCacheTTL == 0 {
		o.IntrospectionCacheTTL = time.Minute
	}
	return &Verifier{
		opts: o,
		jwks: &jwksCache{
			url:         o.JWKSURL,
			client:      o.HTTPClient,
			now:         o.Now,
			maxAge:      o.JWKSMaxAge,
			minInterval: o.JWKSMinRefreshInterval,
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
		log:        o.Logger,
		introCache: make(map[string]time.Time),
	}
}

// errUnavailable is returned (and surfaces as HTTP 500) when the token could
// not be checked because a dependency failed. It deliberately carries no detail.
var errUnavailable = errors.New("token verification unavailable")

// Verify is an auth.TokenVerifier. Rejections unwrap to auth.ErrInvalidToken
// and carry no detail for the client; the reason is logged instead.
// Scope enforcement (403) is left to auth.RequireBearerToken via TokenInfo.Scopes.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	info, reason, err := v.verify(ctx, token)
	if err != nil {
		v.log.ErrorContext(ctx, "token verification failed", "error", err)
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
			return nil, fmt.Errorf("alg %q does not match key", alg)
		}
		return k.key, nil
	})
	if keyErr != nil {
		return nil, "", keyErr
	}
	if err != nil {
		return nil, err.Error(), nil
	}

	// RFC 9068 section 4: the typ header must be at+jwt (optionally with the
	// application/ prefix). This rejects ID tokens signed with the same key.
	typ, _ := tok.Header["typ"].(string)
	if t := strings.ToLower(typ); t != "at+jwt" && t != "application/at+jwt" {
		return nil, "typ is not at+jwt", nil
	}

	subject, _ := claims[v.opts.SubjectClaim].(string)
	if subject == "" {
		return nil, "subject claim missing", nil
	}
	if !strings.EqualFold(subject, v.opts.AllowedSubject) {
		return nil, "subject not allowed", nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, "bad exp", nil
	}

	scopeStr, _ := claims["scope"].(string)

	jti, _ := claims["jti"].(string)
	if v.opts.IntrospectionURL != "" {
		active, err := v.introspect(ctx, token, jti, exp.Time)
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

func (v *Verifier) introspect(ctx context.Context, token, jti string, exp time.Time) (bool, error) {
	now := v.opts.Now()
	if jti != "" {
		v.introMu.Lock()
		until, ok := v.introCache[jti]
		for k, t := range v.introCache {
			if now.After(t) {
				delete(v.introCache, k)
			}
		}
		v.introMu.Unlock()
		if ok && now.Before(until) {
			return true, nil
		}
	}

	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.opts.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.opts.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("introspect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil // Kanidm answers 401 for tokens it cannot verify
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("introspect: status %d", resp.StatusCode)
	}
	var r struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return false, fmt.Errorf("introspect: %w", err)
	}
	if r.Active && jti != "" {
		until := now.Add(v.opts.IntrospectionCacheTTL)
		if exp.Before(until) {
			until = exp
		}
		v.introMu.Lock()
		v.introCache[jti] = until
		v.introMu.Unlock()
	}
	return r.Active, nil
}
