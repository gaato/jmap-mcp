package tokenauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/gaato/jmap-mcp/internal/logsafe"
	"golang.org/x/sync/singleflight"
)

// jwk is the subset of RFC 7517 fields needed to reconstruct verification keys.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type verificationKey struct {
	alg string // JWS alg this key may be used with
	key crypto.PublicKey
}

// jwksCache fetches a JWKS document lazily and refetches it when a token
// references an unknown kid (key rotation) or when the cached copy is older
// than softMaxAge.
//
//   - Refetches are throttled to one per minInterval, also while no keys are
//     cached (startup, outage), so tokens with random kids cannot be used to
//     hammer the authorization server.
//   - Concurrent misses share one fetch (singleflight). The fetch runs
//     detached from the request context with its own timeout, so a client
//     that disconnects cannot waste the refresh slot, and the mutex is never
//     held during network I/O.
//   - If refreshing fails, cached keys stay usable for a short grace period
//     after softMaxAge; after that the cache fails closed.
type jwksCache struct {
	url          string
	client       *http.Client
	now          func() time.Time
	softMaxAge   time.Duration
	grace        time.Duration
	minInterval  time.Duration
	fetchTimeout time.Duration
	log          *slog.Logger

	sf singleflight.Group

	mu        sync.Mutex
	keys      map[string]verificationKey
	fetchedAt time.Time
	triedAt   time.Time
}

var (
	errUnknownKID   = errors.New("unknown kid")
	errNoValidKeys  = errors.New("no valid signing keys (JWKS unavailable or expired)")
	errJWKSThrottle = errors.New("jwks refresh throttled")
	errNoUsableKeys = errors.New("jwks contains no usable signing keys")
)

func (c *jwksCache) cached(kid string) (k verificationKey, found, fresh, usable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	age := c.now().Sub(c.fetchedAt)
	have := c.keys != nil
	k, found = c.keys[kid]
	return k, found, have && age <= c.softMaxAge, have && age <= c.softMaxAge+c.grace
}

func (c *jwksCache) lookup(ctx context.Context, kid string) (verificationKey, error) {
	if k, found, fresh, _ := c.cached(kid); found && fresh {
		return k, nil
	}
	// Unknown kid or stale cache: try a (throttled, shared) refresh. Its
	// error does not matter here; the cache state afterwards decides.
	ch := c.sf.DoChan("refresh", func() (any, error) { return nil, c.refresh(ctx) })
	var refreshErr error
	select {
	case r := <-ch:
		if r.Err != nil && !errors.Is(r.Err, errJWKSThrottle) {
			refreshErr = r.Err
		}
	case <-ctx.Done():
		return verificationKey{}, ctx.Err()
	}
	k, found, _, usable := c.cached(kid)
	switch {
	case !usable:
		return verificationKey{}, errors.Join(errNoValidKeys, refreshErr)
	case !found:
		return verificationKey{}, errUnknownKID
	}
	return k, nil
}

func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	now := c.now()
	if !c.triedAt.IsZero() && now.Sub(c.triedAt) < c.minInterval {
		c.mu.Unlock()
		return errJWKSThrottle
	}
	c.triedAt = now
	c.mu.Unlock()

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
	defer cancel()
	keys, err := c.fetch(fctx)
	if err != nil {
		if c.log != nil {
			c.log.WarnContext(ctx, "jwks refresh failed", logsafe.Attrs(err)...)
		}
		return err
	}
	c.mu.Lock()
	c.keys, c.fetchedAt = keys, now
	c.mu.Unlock()
	return nil
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]verificationKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, logsafe.Wrap("fetch jwks", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &logsafe.Status{Op: "fetch jwks", Code: resp.StatusCode}
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, logsafe.Wrap("decode jwks", err)
	}
	keys := make(map[string]verificationKey)
	for _, j := range doc.Keys {
		if j.Kid == "" || (j.Use != "" && j.Use != "sig") {
			continue
		}
		k, err := j.verificationKey()
		if err != nil {
			continue // skip keys we cannot use instead of failing the whole set
		}
		keys[j.Kid] = k
	}
	if len(keys) == 0 {
		// Treat like a failed fetch: keep the previous keys (within the
		// grace period) instead of caching an empty set as fresh.
		return nil, logsafe.Wrap("fetch jwks", errNoUsableKeys)
	}
	return keys, nil
}

func (j jwk) verificationKey() (verificationKey, error) {
	switch j.Kty {
	case "EC":
		if j.Crv != "P-256" || (j.Alg != "" && j.Alg != "ES256") {
			return verificationKey{}, errors.New("unsupported EC key")
		}
		x, err1 := base64.RawURLEncoding.DecodeString(j.X)
		y, err2 := base64.RawURLEncoding.DecodeString(j.Y)
		if err := errors.Join(err1, err2); err != nil || len(x) != 32 || len(y) != 32 {
			return verificationKey{}, errors.New("bad EC coordinates")
		}
		// ParseUncompressedPublicKey also rejects points that are not on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return verificationKey{}, err
		}
		return verificationKey{alg: "ES256", key: pub}, nil
	case "RSA":
		if j.Alg != "" && j.Alg != "RS256" {
			return verificationKey{}, errors.New("unsupported RSA alg")
		}
		n, err1 := b64Int(j.N)
		e, err2 := b64Int(j.E)
		if err := errors.Join(err1, err2); err != nil {
			return verificationKey{}, err
		}
		// A real RSA modulus and public exponent are always odd; reject
		// anything else (and small or oversized values) as unusable.
		if n.BitLen() < 2048 || n.Bit(0) == 0 ||
			!e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 || e.Bit(0) == 0 {
			return verificationKey{}, errors.New("weak or malformed RSA key")
		}
		return verificationKey{alg: "RS256", key: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
	default:
		return verificationKey{}, errors.New("unsupported kty")
	}
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("bad base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}
