package tokenauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	testIssuer   = "https://id.example.net/oauth2/openid/mcp_jmap"
	testAudience = "mcp_jmap"
	testSubject  = "0b4c6a8e-7f0e-4b7b-9d4e-2f3a5c6d7e8f"
)

type signer struct {
	kid string
	key *ecdsa.PrivateKey
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{kid: kid, key: k}
}

func (s signer) jwk() map[string]string {
	raw, _ := s.key.PublicKey.Bytes() // uncompressed point: 0x04 || X || Y
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]string{"kty": "EC", "crv": "P-256", "kid": s.kid, "use": "sig", "alg": "ES256",
		"x": enc(raw[1:33]), "y": enc(raw[33:])}
}

// testEnv is a JWKS endpoint plus a controllable clock.
type testEnv struct {
	t       *testing.T
	srv     *httptest.Server
	fetches atomic.Int32
	mu      sync.Mutex
	keys    []signer
	now     time.Time
}

func newEnv(t *testing.T, keys ...signer) *testEnv {
	e := &testEnv{t: t, keys: keys, now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.fetches.Add(1)
		e.mu.Lock()
		defer e.mu.Unlock()
		var ks []map[string]string
		for _, k := range e.keys {
			ks = append(ks, k.jwk())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *testEnv) setKeys(keys ...signer) {
	e.mu.Lock()
	e.keys = keys
	e.mu.Unlock()
}

func (e *testEnv) clock() time.Time { return e.now }

func (e *testEnv) verifier(mod func(*Options)) *Verifier {
	o := Options{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: e.srv.URL,
		AllowedSubject: testSubject, Now: e.clock,
	}
	if mod != nil {
		mod(&o)
	}
	return New(o)
}

// kanidmClaims mirrors what Kanidm 1.10.4 puts into an RFC 9068 access token.
func (e *testEnv) kanidmClaims() jwt.MapClaims {
	iat := e.now.Unix()
	return jwt.MapClaims{
		"iss": testIssuer, "sub": testSubject, "aud": testAudience,
		"exp": iat + 900, "nbf": iat, "iat": iat,
		"jti": "6f1d2c3b-0000-4000-8000-000000000001", "client_id": testAudience,
		"scope": "mail_read offline_access", "session_id": "6f1d2c3b-0000-4000-8000-000000000001",
		"parent_session_id": "6f1d2c3b-0000-4000-8000-000000000002",
	}
}

func sign(t *testing.T, s signer, claims jwt.MapClaims, typ string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = s.kid
	if typ == "" {
		delete(tok.Header, "typ")
	} else {
		tok.Header["typ"] = typ
	}
	str, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatal(err)
	}
	return str
}

func TestVerifyValidKanidmToken(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	v := env.verifier(nil)
	info, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.UserID != testSubject || len(info.Scopes) != 2 || info.Scopes[0] != "mail_read" {
		t.Fatalf("info = %+v", info)
	}
	if !info.Expiration.Equal(env.now.Add(15 * time.Minute)) {
		t.Fatalf("exp = %v", info.Expiration)
	}
}

func TestVerifyRejections(t *testing.T) {
	k := newSigner(t, "k1")
	other := newSigner(t, "k1") // same kid, different key: bad signature
	env := newEnv(t, k)

	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
		typ    string
		signer signer
	}{
		{name: "wrong aud", mutate: func(c jwt.MapClaims) { c["aud"] = "other_client" }},
		{name: "aud is the MCP URL", mutate: func(c jwt.MapClaims) { c["aud"] = "https://mail-mcp.example.net/mcp" }},
		{name: "wrong iss", mutate: func(c jwt.MapClaims) { c["iss"] = "https://id.example.net/oauth2/openid/other" }},
		{name: "expired", mutate: func(c jwt.MapClaims) {
			c["exp"] = env.now.Add(-time.Minute).Unix()
			c["iat"] = env.now.Add(-16 * time.Minute).Unix()
			c["nbf"] = c["iat"]
		}},
		{name: "not yet valid", mutate: func(c jwt.MapClaims) { c["nbf"] = env.now.Add(5 * time.Minute).Unix() }},
		{name: "missing exp", mutate: func(c jwt.MapClaims) { delete(c, "exp") }},
		{name: "wrong typ (id token)", typ: "JWT"},
		{name: "missing typ", typ: "-"},
		{name: "wrong subject", mutate: func(c jwt.MapClaims) { c["sub"] = "11111111-2222-3333-4444-555555555555" }},
		{name: "missing subject", mutate: func(c jwt.MapClaims) { delete(c, "sub") }},
		{name: "bad signature", signer: other},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := env.kanidmClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			typ := "at+jwt"
			switch tc.typ {
			case "-":
				typ = ""
			case "":
			default:
				typ = tc.typ
			}
			s := k
			if tc.signer.key != nil {
				s = tc.signer
			}
			_, err := env.verifier(nil).Verify(context.Background(), sign(t, s, c, typ), nil)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyRejectsHS256AndGarbage(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	v := env.verifier(nil)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, env.kanidmClaims())
	tok.Header["kid"] = "k1"
	tok.Header["typ"] = "at+jwt"
	hs, _ := tok.SignedString([]byte("secret"))
	for _, s := range []string{hs, "not-a-jwt", ""} {
		if _, err := v.Verify(context.Background(), s, nil); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("%q: err = %v", s, err)
		}
	}
}

func TestVerifyLeeway(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	c := env.kanidmClaims()
	c["exp"] = env.now.Add(-10 * time.Second).Unix() // within the default 30s leeway
	if _, err := env.verifier(nil).Verify(context.Background(), sign(t, k, c, "at+jwt"), nil); err != nil {
		t.Fatalf("token inside leeway rejected: %v", err)
	}
}

func TestUnknownKidRefreshesJWKS(t *testing.T) {
	k1, k2 := newSigner(t, "k1"), newSigner(t, "k2")
	env := newEnv(t, k1)
	v := env.verifier(nil)

	if _, err := v.Verify(context.Background(), sign(t, k1, env.kanidmClaims(), "at+jwt"), nil); err != nil {
		t.Fatal(err)
	}
	if n := env.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d", n)
	}

	// Key rotation: k2 appears. Within the rate-limit window a new kid is
	// not fetched, so the token is rejected without hitting the server.
	env.setKeys(k1, k2)
	tok2 := sign(t, k2, env.kanidmClaims(), "at+jwt")
	if _, err := v.Verify(context.Background(), tok2, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
	if n := env.fetches.Load(); n != 1 {
		t.Fatalf("rate limit not applied: fetches = %d", n)
	}

	env.now = env.now.Add(time.Minute)
	tok2 = sign(t, k2, env.kanidmClaims(), "at+jwt")
	if _, err := v.Verify(context.Background(), tok2, nil); err != nil {
		t.Fatalf("after refresh: %v", err)
	}
	if n := env.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
	// k1 still cached and valid without a fetch.
	if _, err := v.Verify(context.Background(), sign(t, k1, env.kanidmClaims(), "at+jwt"), nil); err != nil {
		t.Fatal(err)
	}
	if n := env.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestJWKSUnavailableIsNotInvalidToken(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	v := env.verifier(func(o *Options) { o.JWKSURL = "http://127.0.0.1:1/jwks" })
	_, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil)
	if err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want an internal error", err)
	}
}

func TestIntrospection(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	var active atomic.Bool
	var calls atomic.Int32
	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.PostFormValue("token") == "" {
			t.Errorf("unexpected introspection request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": active.Load()})
	}))
	defer intro.Close()

	v := env.verifier(func(o *Options) { o.IntrospectionURL = intro.URL })
	tok := sign(t, k, env.kanidmClaims(), "at+jwt")

	if _, err := v.Verify(context.Background(), tok, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	active.Store(true)
	for range 2 {
		if _, err := v.Verify(context.Background(), tok, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("introspection calls = %d, want 2 (second active result cached)", n)
	}
}

func TestCustomSubjectClaim(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	v := env.verifier(func(o *Options) { o.SubjectClaim = "client_id"; o.AllowedSubject = testAudience })
	if _, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil); err != nil {
		t.Fatal(err)
	}
}

func timeNow() time.Time { return time.Now().Truncate(time.Second) }
