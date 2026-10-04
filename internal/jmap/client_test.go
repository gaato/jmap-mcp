package jmap_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gaato/jmap-mcp/internal/jmap"
	"github.com/gaato/jmap-mcp/internal/jmap/jmaptest"
)

func newClient(t *testing.T) (*jmap.Client, *jmaptest.Server) {
	t.Helper()
	srv := jmaptest.New()
	t.Cleanup(srv.Close)
	return jmaptest.MustClient(t, srv.SessionURL(), jmaptest.Username, jmaptest.Password), srv
}

func TestSessionDiscoveryAndMailboxes(t *testing.T) {
	c, srv := newClient(t)
	mbs, err := c.Mailboxes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(mbs) != 3 || mbs[0].Name != "Inbox" || mbs[0].Role != "inbox" || mbs[0].UnreadEmails != 1 {
		t.Fatalf("unexpected mailboxes: %+v", mbs)
	}
	// Second call reuses the cached session.
	if _, err := c.Mailboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.Called(); !slices.Equal(got, []string{"Mailbox/get", "Mailbox/get"}) {
		t.Fatalf("called %v", got)
	}
}

func TestSearchEmailsUsesResultReference(t *testing.T) {
	c, srv := newClient(t)
	list, total, err := c.SearchEmails(context.Background(), jmap.EmailFilter{Text: "lunch"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(list) != 2 {
		t.Fatalf("total=%d len=%d", total, len(list))
	}
	// Query order (newest first) is kept even though the fake reverses Email/get.
	if list[0].ID != "e2" || list[1].ID != "e1" {
		t.Fatalf("order: %s, %s", list[0].ID, list[1].ID)
	}
	if list[1].From[0].Email != "alice@example.org" || list[1].MessageID[0] != "a1@example.org" {
		t.Fatalf("summary: %+v", list[1])
	}
	if got := srv.Called(); !slices.Equal(got, []string{"Email/query", "Email/get"}) {
		t.Fatalf("called %v (want one request with a back-reference)", got)
	}
}

func TestSearchEmailsFilters(t *testing.T) {
	c, _ := newClient(t)
	list, _, err := c.SearchEmails(context.Background(), jmap.EmailFilter{
		InMailbox: "mb-inbox", After: "2026-09-02T00:00:00Z",
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "e3" {
		t.Fatalf("got %+v", list)
	}
}

func TestGetEmailBody(t *testing.T) {
	c, _ := newClient(t)
	e, err := c.GetEmail(context.Background(), "e4", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.TextBody) != 1 || e.TextBody[0].Type != "text/plain" {
		t.Fatalf("textBody: %+v", e.TextBody)
	}
	bv := e.BodyValues[e.TextBody[0].PartID]
	if len(bv.Value) != 100 || !bv.IsTruncated {
		t.Fatalf("body value len=%d truncated=%v", len(bv.Value), bv.IsTruncated)
	}
}

func TestGetEmailNotFound(t *testing.T) {
	c, _ := newClient(t)
	_, err := c.GetEmail(context.Background(), "nope", 100)
	var me *jmap.MethodError
	if !errors.As(err, &me) || me.Type != "notFound" {
		t.Fatalf("err = %v", err)
	}
}

func TestGetThread(t *testing.T) {
	c, _ := newClient(t)
	list, total, err := c.GetThread(context.Background(), "t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(list) != 2 || list[0].ID != "e1" || list[1].ID != "e2" {
		t.Fatalf("total=%d list=%+v", total, list)
	}
	list, total, err = c.GetThread(context.Background(), "t1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(list) != 1 || list[0].ID != "e2" {
		t.Fatalf("limit should keep the newest: total=%d list=%+v", total, list)
	}
	if _, _, err := c.GetThread(context.Background(), "missing", 10); err == nil {
		t.Fatal("expected notFound error")
	}
}

func TestMethodErrorMapping(t *testing.T) {
	c, srv := newClient(t)
	srv.FailMethod = map[string]string{"Mailbox/get": "forbidden"}
	_, err := c.Mailboxes(context.Background())
	var me *jmap.MethodError
	if !errors.As(err, &me) || me.Type != "forbidden" || me.Method != "Mailbox/get" {
		t.Fatalf("err = %v", err)
	}
}

func TestBadCredentials(t *testing.T) {
	srv := jmaptest.New()
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.SessionURL(), jmaptest.Username, "wrong")
	if _, err := c.Mailboxes(context.Background()); !errors.Is(err, jmap.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestErrorProblemJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"apiUrl":"/api","primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},"state":"x"}`))
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:jmap:error:limit","status":400,"detail":"too many"}`))
	}))
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.URL+"/session", "u", "p")
	_, err := c.Mailboxes(context.Background())
	var re *jmap.RequestError
	if !errors.As(err, &re) || re.Status != 400 || re.Type != "urn:ietf:params:jmap:error:limit" {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionWithoutMailAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiUrl":"/api","primaryAccounts":{},"state":"x"}`))
	}))
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.URL, "u", "p")
	if _, err := c.Mailboxes(context.Background()); err == nil || !strings.Contains(err.Error(), "primary mail account") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmailURL(t *testing.T) {
	if got := jmap.EmailURL([]string{"a b@example.org"}); got != "mid:a%20b@example.org" {
		t.Fatalf("got %q", got)
	}
	if got := jmap.EmailURL(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

// recorder counts requests and whether they carried credentials.
func recorder(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"apiUrl":"/api","primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},"state":"x","methodResponses":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestAPIURLOnOtherOriginRefused(t *testing.T) {
	other, hits := recorder(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiUrl":"` + other.URL + `/api","primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},"state":"x"}`))
	}))
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.URL, "u", "p")
	if _, err := c.Mailboxes(context.Background()); err == nil || !strings.Contains(err.Error(), "not the configured JMAP origin") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("credentials were sent to the other origin")
	}
}

func TestPlainHTTPAPIURLRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"apiUrl":"http://mail.example.net/api","primaryAccounts":{"urn:ietf:params:jmap:mail":"a"},"state":"x"}`))
	}))
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.URL, "u", "p")
	if _, err := c.Mailboxes(context.Background()); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectToOtherOriginRefused(t *testing.T) {
	other, hits := recorder(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/jmap/session", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := jmaptest.MustClient(t, srv.URL+"/.well-known/jmap", "u", "p")
	if _, err := c.Mailboxes(context.Background()); err == nil || !strings.Contains(err.Error(), "not the configured JMAP origin") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("redirect to another origin was followed")
	}
}

func TestRedirectToExplicitlyAllowedOrigin(t *testing.T) {
	mail := jmaptest.New()
	defer mail.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, mail.URL+"/jmap/session", http.StatusTemporaryRedirect)
	}))
	defer front.Close()
	c, err := jmap.NewClient(front.URL+"/.well-known/jmap", mail.URL, jmaptest.Username, jmaptest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Mailboxes(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRejectsPlainHTTP(t *testing.T) {
	if _, err := jmap.NewClient("http://mail.example.net/.well-known/jmap", "", "u", "p"); err == nil {
		t.Fatal("plain http session URL accepted")
	}
	if _, err := jmap.NewClient("https://mail.example.net/.well-known/jmap", "http://other.example.net", "u", "p"); err == nil {
		t.Fatal("plain http extra origin accepted")
	}
}
