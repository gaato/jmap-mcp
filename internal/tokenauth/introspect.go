package tokenauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// NegativeIntrospectionCacheTTL bounds how long an "inactive" answer is
// reused. Revocation is final, so this only limits memory, not correctness.
const NegativeIntrospectionCacheTTL = 5 * time.Minute

const introspectionCacheSize = 4096

type introEntry struct {
	active bool
	until  time.Time
}

// introspector asks the authorization server whether a (signature-verified)
// token is still active. Answers are cached per token, positive ones for at
// most MaxIntrospectionCacheTTL and negative ones for
// NegativeIntrospectionCacheTTL, both never beyond the token's exp; the cache
// is bounded. Concurrent checks of the same token share one request, which
// runs detached from the caller with its own timeout. A replayed revoked
// token therefore costs at most one introspection call per cache period.
type introspector struct {
	url         string
	client      *http.Client
	now         func() time.Time
	positiveTTL time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	maxEntries  int

	sf    singleflight.Group
	mu    sync.Mutex
	cache map[[32]byte]introEntry // keyed by SHA-256 of the token
}

func (in *introspector) cached(key [32]byte) (introEntry, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	e, ok := in.cache[key]
	if ok && in.now().Before(e.until) {
		return e, true
	}
	return introEntry{}, false
}

func (in *introspector) store(key [32]byte, active bool, exp time.Time) {
	now := in.now()
	until := now.Add(in.negativeTTL)
	if active {
		until = now.Add(in.positiveTTL)
	}
	if exp.Before(until) {
		until = exp
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.cache) >= in.maxEntries {
		for k, e := range in.cache {
			if !now.Before(e.until) {
				delete(in.cache, k)
			}
		}
		// Still full: drop arbitrary entries; they are only an optimisation.
		for k := range in.cache {
			if len(in.cache) < in.maxEntries {
				break
			}
			delete(in.cache, k)
		}
	}
	in.cache[key] = introEntry{active: active, until: until}
}

func (in *introspector) check(ctx context.Context, token string, exp time.Time) (bool, error) {
	key := sha256.Sum256([]byte(token))
	if e, ok := in.cached(key); ok {
		return e.active, nil
	}
	ch := in.sf.DoChan(hex.EncodeToString(key[:]), func() (any, error) {
		if e, ok := in.cached(key); ok { // filled while we were queued
			return e.active, nil
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), in.timeout)
		defer cancel()
		active, err := in.request(rctx, token)
		if err != nil {
			return false, err
		}
		in.store(key, active, exp)
		return active, nil
	})
	select {
	case r := <-ch:
		if r.Err != nil {
			return false, r.Err
		}
		return r.Val.(bool), nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (in *introspector) request(ctx context.Context, token string) (bool, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.url, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := in.client.Do(req)
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
	return r.Active, nil
}
