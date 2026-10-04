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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
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
// references an unknown kid (key rotation) or when the cached copy is stale.
// Refetches are rate limited so that tokens with random kids cannot be used to
// hammer the authorization server.
type jwksCache struct {
	url         string
	client      *http.Client
	now         func() time.Time
	maxAge      time.Duration
	minInterval time.Duration

	mu        sync.Mutex
	keys      map[string]verificationKey
	fetchedAt time.Time
	triedAt   time.Time
}

func (c *jwksCache) lookup(ctx context.Context, kid string) (verificationKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	stale := c.keys == nil || now.Sub(c.fetchedAt) > c.maxAge
	k, ok := c.keys[kid]
	if ok && !stale {
		return k, nil
	}
	if c.keys == nil || now.Sub(c.triedAt) >= c.minInterval {
		c.triedAt = now
		keys, err := c.fetch(ctx)
		if err != nil {
			if ok {
				// Keep serving a known key if the refresh of a stale cache fails.
				return k, nil
			}
			return verificationKey{}, err
		}
		c.keys, c.fetchedAt = keys, now
		k, ok = c.keys[kid]
	}
	if !ok {
		return verificationKey{}, errUnknownKID
	}
	return k, nil
}

var errUnknownKID = errors.New("unknown kid")

func (c *jwksCache) fetch(ctx context.Context) (map[string]verificationKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
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
		if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
			return verificationKey{}, errors.New("weak RSA key")
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
