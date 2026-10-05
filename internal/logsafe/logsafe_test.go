package logsafe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func render(attrs []any) string { return fmt.Sprint(attrs...) }

func TestAttrsRedactsURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	c := &http.Client{Timeout: 20 * time.Millisecond}
	_, err := c.Get(srv.URL + "/secret/path?token=SECRET")
	if err == nil {
		t.Fatal("expected timeout")
	}
	got := render(Attrs(Wrap("fetch jwks", err)))
	if strings.Contains(got, "SECRET") || strings.Contains(got, "/secret") {
		t.Fatalf("leaked: %s", got)
	}
	for _, want := range []string{"fetch jwks", srv.URL, "timeout"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestKinds(t *testing.T) {
	var syn error
	syn = json.Unmarshal([]byte("{UPSTREAM TEXT"), &struct{}{})
	cases := map[string]error{
		"cancelled":         fmt.Errorf("x: %w", context.Canceled),
		"refused_by_policy": fmt.Errorf("redirect to evil: %w", ErrRefused),
		"decode":            Wrap("decode", syn),
		"http_status":       &Status{Op: "introspect", Code: 502},
		"error":             errors.New("UPSTREAM TEXT"),
	}
	for want, err := range cases {
		if got := Kind(err); got != want {
			t.Errorf("%v: kind %s, want %s", err, got, want)
		}
		if s := render(Attrs(err)); strings.Contains(s, "UPSTREAM") || strings.Contains(s, "evil") {
			t.Errorf("leaked: %s", s)
		}
	}
	if s := render(Attrs(&Status{Op: "introspect", Code: 502})); !strings.Contains(s, "502") {
		t.Errorf("status missing: %s", s)
	}
}
