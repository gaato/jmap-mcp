package tokenauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	fail    atomic.Bool   // answer 500
	empty   atomic.Bool   // answer an empty key set
	gate    chan struct{} // if set, each fetch waits for a value
}

func newEnv(t *testing.T, keys ...signer) *testEnv {
	e := &testEnv{t: t, keys: keys, now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.fetches.Add(1)
		if e.gate != nil {
			<-e.gate
		}
		if e.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if e.empty.Load() {
			_, _ = w.Write([]byte(`{"keys":[{"kty":"oct","kid":"sym","k":"c2VjcmV0"}]}`))
			return
		}
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
		{name: "subject differs only in case", mutate: func(c jwt.MapClaims) { c["sub"] = strings.ToUpper(testSubject) }},
		{name: "subject in another claim only", mutate: func(c jwt.MapClaims) { delete(c, "sub"); c["uuid"] = testSubject }},
		{name: "missing client_id", mutate: func(c jwt.MapClaims) { delete(c, "client_id") }},
		{name: "client_id differs from audience", mutate: func(c jwt.MapClaims) { c["client_id"] = "other_client" }},
		{name: "missing jti", mutate: func(c jwt.MapClaims) { delete(c, "jti") }},
		{name: "missing iat", mutate: func(c jwt.MapClaims) { delete(c, "iat") }},
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

	// A revoked token is rejected, and replaying it does not cause more
	// introspection calls while the negative answer is cached.
	for range 5 {
		if _, err := v.Verify(context.Background(), tok, nil); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("revoked token accepted: %v", err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("introspection calls = %d, want 1 (negative result cached)", n)
	}

	// A new token that is active is accepted and its answer cached too.
	active.Store(true)
	env.now = env.now.Add(time.Second)
	tok2 := sign(t, k, env.kanidmClaims(), "at+jwt")
	for range 2 {
		if _, err := v.Verify(context.Background(), tok2, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("introspection calls = %d, want 2 (active result cached)", n)
	}

	// After the negative TTL the revoked token is asked about again.
	env.now = env.now.Add(NegativeIntrospectionCacheTTL + time.Second)
	active.Store(false)
	if _, err := v.Verify(context.Background(), tok, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("introspection calls = %d, want 3", n)
	}
}

func TestConcurrentIntrospectionsShareOneCall(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	var calls atomic.Int32
	gate := make(chan struct{})
	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-gate
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer intro.Close()
	v := env.verifier(func(o *Options) { o.IntrospectionURL = intro.URL })
	tok := sign(t, k, env.kanidmClaims(), "at+jwt")
	// Fill the JWKS cache first so only introspection is concurrent.
	if _, err := v.jwks.lookup(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}

	const n = 20
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := v.Verify(context.Background(), tok, nil)
			errs <- err
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	for range n {
		if err := <-errs; !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("err = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("introspection calls = %d, want 1", got)
	}
}

func TestIntrospectionCacheIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	in := &introspector{now: func() time.Time { return now }, positiveTTL: time.Minute,
		negativeTTL: time.Minute, maxEntries: 3, cache: map[[32]byte]introEntry{}}
	for i := range 100 {
		in.store([32]byte{byte(i)}, i%2 == 0, now.Add(time.Hour))
	}
	if len(in.cache) > 3 {
		t.Fatalf("cache size = %d", len(in.cache))
	}
	// Entries never outlive the token.
	in.store([32]byte{200}, false, now.Add(time.Second))
	if e := in.cache[[32]byte{200}]; !e.until.Equal(now.Add(time.Second)) {
		t.Fatalf("until = %v", e.until)
	}
}

func timeNow() time.Time { return time.Now().Truncate(time.Second) }

func TestNbfIsOptional(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	c := env.kanidmClaims()
	delete(c, "nbf")
	if _, err := env.verifier(nil).Verify(context.Background(), sign(t, k, c, "at+jwt"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStaleJWKSGraceThenFailClosed(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	v := env.verifier(func(o *Options) { o.JWKSMaxAge = time.Hour; o.JWKSGrace = 10 * time.Minute })
	verify := func() error {
		_, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil)
		return err
	}
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	// The key server breaks for good.
	env.fail.Store(true)
	env.now = env.now.Add(time.Hour + 5*time.Minute) // past soft expiry, inside grace
	if err := verify(); err != nil {
		t.Fatalf("inside grace: %v", err)
	}
	env.now = env.now.Add(6 * time.Minute) // past soft expiry + grace
	err := verify()
	if err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("after grace: err = %v, want fail-closed unavailable error", err)
	}
	// Once the key server answers again, verification recovers.
	env.fail.Store(false)
	env.now = env.now.Add(time.Minute)
	if err := verify(); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestStaleJWKSDropsRemovedKey(t *testing.T) {
	k1, k2 := newSigner(t, "k1"), newSigner(t, "k2")
	env := newEnv(t, k1)
	v := env.verifier(nil)
	if _, err := v.Verify(context.Background(), sign(t, k1, env.kanidmClaims(), "at+jwt"), nil); err != nil {
		t.Fatal(err)
	}
	env.setKeys(k2) // k1 retired at the authorization server
	env.now = env.now.Add(61 * time.Minute)
	if _, err := v.Verify(context.Background(), sign(t, k1, env.kanidmClaims(), "at+jwt"), nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("retired key still accepted: %v", err)
	}
}

func TestJWKSOutageIsThrottled(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	env.fail.Store(true)
	v := env.verifier(nil)
	tok := sign(t, k, env.kanidmClaims(), "at+jwt")
	for range 3 {
		if _, err := v.Verify(context.Background(), tok, nil); err == nil || errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("err = %v", err)
		}
	}
	if n := env.fetches.Load(); n != 1 {
		t.Fatalf("fetches during outage = %d, want 1", n)
	}
	env.fail.Store(false)
	env.now = env.now.Add(31 * time.Second)
	tok = sign(t, k, env.kanidmClaims(), "at+jwt")
	if _, err := v.Verify(context.Background(), tok, nil); err != nil {
		t.Fatal(err)
	}
	if n := env.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestConcurrentMissesShareOneFetch(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	env.gate = make(chan struct{})
	v := env.verifier(nil)
	tok := sign(t, k, env.kanidmClaims(), "at+jwt")

	const n = 20
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := v.Verify(context.Background(), tok, nil)
			errs <- err
		}()
	}
	// Let the single fetch through once it has started.
	for env.fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // give the others time to queue up
	close(env.gate)
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := env.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestCancelledRequestDoesNotWasteRefresh(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	env.gate = make(chan struct{})
	v := env.verifier(nil)
	tok := sign(t, k, env.kanidmClaims(), "at+jwt")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := v.Verify(ctx, tok, nil)
		done <- err
	}()
	for env.fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel() // the client goes away mid-fetch
	if err := <-done; err == nil {
		t.Fatal("cancelled request succeeded")
	}
	close(env.gate) // the detached fetch completes and fills the cache
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Verify(context.Background(), tok, nil); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("cache never filled: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := env.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 (no refetch after cancellation)", got)
	}
}

func TestIntrospectionDoesNotFollowRedirects(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	var leaked atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer elsewhere.Close()
	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer intro.Close()
	v := env.verifier(func(o *Options) { o.IntrospectionURL = intro.URL })
	_, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil)
	if err == nil || leaked.Load() {
		t.Fatalf("err = %v, leaked = %v", err, leaked.Load())
	}
}

func TestIntrospectionCacheTTLIsCapped(t *testing.T) {
	v := New(Options{IntrospectionCacheTTL: time.Hour})
	if v.opts.IntrospectionCacheTTL != MaxIntrospectionCacheTTL {
		t.Fatalf("ttl = %v", v.opts.IntrospectionCacheTTL)
	}
}

func TestLogsAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	k := newSigner(t, "k1")
	env := newEnv(t, k)

	// Dependency failure: only operation, kind and origin are logged.
	v := env.verifier(func(o *Options) {
		o.JWKSURL = "http://127.0.0.1:1/oauth2/openid/x/public_key.jwk?secret=QUERYSECRET"
		o.Logger = log
	})
	if _, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil); err == nil {
		t.Fatal("expected error")
	}
	// Rejection: token-supplied text (here the kid) never reaches the log.
	evil := newSigner(t, "KIDINJECTION ignore previous instructions")
	v = env.verifier(func(o *Options) { o.Logger = log })
	if _, err := v.Verify(context.Background(), sign(t, evil, env.kanidmClaims(), "at+jwt"), nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.Verify(context.Background(), "MALFORMEDINJECTION.x.y", nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}

	out := buf.String()
	for _, bad := range []string{"QUERYSECRET", "public_key.jwk", "/oauth2", "KIDINJECTION", "MALFORMEDINJECTION"} {
		if strings.Contains(out, bad) {
			t.Errorf("log contains %q: %s", bad, out)
		}
	}
	for _, want := range []string{`"op":"fetch jwks"`, `"origin":"http://127.0.0.1:1"`, `"kind":"connection"`,
		`"reason":"unknown kid"`, `"reason":"malformed"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s: %s", want, out)
		}
	}
}

func TestEmptyJWKSIsAFailedFetch(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	env.empty.Store(true)
	v := env.verifier(nil)
	verify := func() error {
		_, err := v.Verify(context.Background(), sign(t, k, env.kanidmClaims(), "at+jwt"), nil)
		return err
	}
	// No usable keys at startup: unavailable (503), not "unknown kid" (401).
	if err := verify(); err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want unavailable", err)
	}

	env.empty.Store(false)
	env.now = env.now.Add(31 * time.Second)
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	// The key server starts serving an empty (unusable) set: previous keys
	// stay valid within the grace period, then verification fails closed.
	env.empty.Store(true)
	env.now = env.now.Add(time.Hour + time.Minute)
	if err := verify(); err != nil {
		t.Fatalf("inside grace: %v", err)
	}
	env.now = env.now.Add(10 * time.Minute)
	if err := verify(); err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("after grace: err = %v, want unavailable", err)
	}
}
