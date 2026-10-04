// Package jmaptest provides an in-memory fake JMAP server for tests.
package jmaptest

import (
	"testing"

	"encoding/json"
	"github.com/gaato/jmap-mcp/internal/jmap"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
)

const (
	Username  = "gaato@example.net"
	Password  = "app-password"
	AccountID = "acc1"
)

// Email is a fixture message.
type Email struct {
	ID         string
	ThreadID   string
	Mailboxes  []string
	From       string
	To         string
	Subject    string
	ReceivedAt string
	MessageID  string
	Seen       bool
	BodyType   string // text/plain or text/html
	Body       string
}

// Server is a fake JMAP server. It implements just enough of RFC 8620/8621
// for the client: session discovery (with a redirect), Mailbox/get,
// Email/query (simple substring filters), Email/get with result references,
// and Thread/get.
type Server struct {
	*httptest.Server

	Mailboxes []map[string]any
	Emails    []Email

	mu     sync.Mutex
	called []string
	// FailMethod makes the named method return a method error of the given type.
	FailMethod map[string]string
}

// New starts a fake server with default fixtures.
func New() *Server {
	s := &Server{
		Mailboxes: []map[string]any{
			{"id": "mb-inbox", "name": "Inbox", "role": "inbox", "totalEmails": 3, "unreadEmails": 1},
			{"id": "mb-sent", "name": "Sent", "role": "sent", "totalEmails": 1, "unreadEmails": 0},
			{"id": "mb-lists", "name": "Lists", "totalEmails": 1, "unreadEmails": 0},
		},
		Emails: []Email{
			{ID: "e1", ThreadID: "t1", Mailboxes: []string{"mb-inbox"}, From: "alice@example.org", To: Username,
				Subject: "Lunch on Friday", ReceivedAt: "2026-09-01T10:00:00Z", MessageID: "a1@example.org", Seen: true,
				BodyType: "text/plain", Body: "Shall we have lunch on Friday?\r\n-- Alice"},
			{ID: "e2", ThreadID: "t1", Mailboxes: []string{"mb-sent"}, From: Username, To: "alice@example.org",
				Subject: "Re: Lunch on Friday", ReceivedAt: "2026-09-02T09:00:00Z", MessageID: "b2@example.net", Seen: true,
				BodyType: "text/plain", Body: "Sure, noon works."},
			{ID: "e3", ThreadID: "t3", Mailboxes: []string{"mb-inbox"}, From: "news@example.com", To: Username,
				Subject: "Weekly newsletter", ReceivedAt: "2026-09-03T08:00:00Z", MessageID: "n3@example.com",
				BodyType: "text/html", Body: "<html><head><style>p{}</style></head><body><p>Hello &amp; welcome</p>" +
					"<script>alert(1)</script><a href=\"https://evil.example/\">click</a><br>Bye</body></html>"},
			{ID: "e4", ThreadID: "t4", Mailboxes: []string{"mb-lists"}, From: "list@example.com", To: Username,
				Subject: "Long digest", ReceivedAt: "2026-09-04T08:00:00Z",
				BodyType: "text/plain", Body: strings.Repeat("0123456789", 5000)},
		},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// SessionURL is the well-known discovery URL.
func (s *Server) SessionURL() string { return s.URL + "/.well-known/jmap" }

// Called returns the method names invoked so far.
func (s *Server) Called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.called)
}

func problem(w http.ResponseWriter, status int, typ string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "status": status, "detail": "fake"})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/jmap":
		http.Redirect(w, r, "/jmap/session", http.StatusTemporaryRedirect)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != Username || p != Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/jmap/session" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"capabilities":    map[string]any{"urn:ietf:params:jmap:core": map[string]any{}, "urn:ietf:params:jmap:mail": map[string]any{}},
			"accounts":        map[string]any{AccountID: map[string]any{"name": Username}},
			"primaryAccounts": map[string]string{"urn:ietf:params:jmap:mail": AccountID},
			"apiUrl":          "/jmap/api", // relative on purpose
			"state":           "s1",
		})
	case r.URL.Path == "/jmap/api" && r.Method == http.MethodPost:
		s.api(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Using       []string            `json:"using"`
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:notJSON")
		return
	}
	if !slices.Contains(req.Using, "urn:ietf:params:jmap:mail") || !slices.Contains(req.Using, "urn:ietf:params:jmap:core") {
		problem(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:unknownCapability")
		return
	}
	results := map[string]map[string]any{}
	var responses [][]any
	for _, call := range req.MethodCalls {
		var name, id string
		var args map[string]any
		_ = json.Unmarshal(call[0], &name)
		_ = json.Unmarshal(call[1], &args)
		_ = json.Unmarshal(call[2], &id)
		s.mu.Lock()
		s.called = append(s.called, name)
		fail := s.FailMethod[name]
		s.mu.Unlock()

		resolveRefs(args, results)
		var res map[string]any
		switch {
		case fail != "":
			res = map[string]any{"type": fail, "description": "fake failure"}
			name = "error"
		case args["accountId"] != AccountID:
			res, name = map[string]any{"type": "accountNotFound"}, "error"
		default:
			switch name {
			case "Mailbox/get":
				res = map[string]any{"accountId": AccountID, "state": "m1", "list": s.Mailboxes, "notFound": []string{}}
			case "Email/query":
				res = s.emailQuery(args)
			case "Email/get":
				res = s.emailGet(args)
			case "Thread/get":
				res = s.threadGet(args)
			default:
				res, name = map[string]any{"type": "unknownMethod"}, "error"
			}
		}
		results[id] = res
		responses = append(responses, []any{name, res, id})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": responses, "sessionState": "s1"})
}

// resolveRefs handles "#ids" result references with the two paths the client uses.
func resolveRefs(args map[string]any, results map[string]map[string]any) {
	ref, ok := args["#ids"].(map[string]any)
	if !ok {
		return
	}
	delete(args, "#ids")
	prev := results[ref["resultOf"].(string)]
	switch ref["path"] {
	case "/ids":
		var ids []any
		for _, id := range prev["ids"].([]string) {
			ids = append(ids, id)
		}
		args["ids"] = ids
	}
}

func (s *Server) emailQuery(args map[string]any) map[string]any {
	f, _ := args["filter"].(map[string]any)
	str := func(k string) string { v, _ := f[k].(string); return strings.ToLower(v) }
	var matched []Email
	for _, e := range s.Emails {
		switch {
		case str("text") != "" && !strings.Contains(strings.ToLower(e.Subject+" "+e.Body+" "+e.From), str("text")),
			str("from") != "" && !strings.Contains(strings.ToLower(e.From), str("from")),
			str("to") != "" && !strings.Contains(strings.ToLower(e.To), str("to")),
			str("subject") != "" && !strings.Contains(strings.ToLower(e.Subject), str("subject")),
			f["inMailbox"] != nil && !slices.Contains(e.Mailboxes, f["inMailbox"].(string)),
			f["after"] != nil && e.ReceivedAt < f["after"].(string),
			f["before"] != nil && e.ReceivedAt >= f["before"].(string):
			continue
		}
		matched = append(matched, e)
	}
	slices.SortFunc(matched, func(a, b Email) int { return strings.Compare(b.ReceivedAt, a.ReceivedAt) })
	ids := []string{}
	limit := len(matched)
	if l, ok := args["limit"].(float64); ok && int(l) < limit {
		limit = int(l)
	}
	for _, e := range matched[:limit] {
		ids = append(ids, e.ID)
	}
	return map[string]any{"accountId": AccountID, "ids": ids, "total": len(matched), "position": 0}
}

func (s *Server) emailGet(args map[string]any) map[string]any {
	list := []any{}
	notFound := []string{}
	ids, _ := args["ids"].([]any)
	// Return in reverse order: the client must not rely on Email/get order.
	for i := len(ids) - 1; i >= 0; i-- {
		id := ids[i].(string)
		idx := slices.IndexFunc(s.Emails, func(e Email) bool { return e.ID == id })
		if idx < 0 {
			notFound = append(notFound, id)
			continue
		}
		e := s.Emails[idx]
		mbs := map[string]bool{}
		for _, m := range e.Mailboxes {
			mbs[m] = true
		}
		kw := map[string]bool{}
		if e.Seen {
			kw["$seen"] = true
		}
		obj := map[string]any{
			"id": e.ID, "threadId": e.ThreadID, "mailboxIds": mbs, "keywords": kw,
			"from": []map[string]string{{"name": "", "email": e.From}}, "to": []map[string]string{{"email": e.To}}, "cc": nil,
			"subject": e.Subject, "receivedAt": e.ReceivedAt, "sentAt": e.ReceivedAt,
			"preview": firstN(e.Body, 256), "hasAttachment": false,
		}
		if e.MessageID != "" {
			obj["messageId"] = []string{e.MessageID}
		}
		props, _ := args["properties"].([]any)
		if slices.Contains(props, any("textBody")) {
			obj["textBody"] = []map[string]any{{"partId": "1", "type": e.BodyType}}
			bv := map[string]any{}
			if args["fetchTextBodyValues"] == true {
				val, trunc := e.Body, false
				if m, ok := args["maxBodyValueBytes"].(float64); ok && m > 0 && len(val) > int(m) {
					val, trunc = val[:int(m)], true
				}
				bv["1"] = map[string]any{"value": val, "isTruncated": trunc, "isEncodingProblem": false}
			}
			obj["bodyValues"] = bv
		}
		list = append(list, obj)
	}
	return map[string]any{"accountId": AccountID, "state": "e1", "list": list, "notFound": notFound}
}

func (s *Server) threadGet(args map[string]any) map[string]any {
	list := []any{}
	notFound := []string{}
	ids, _ := args["ids"].([]any)
	for _, raw := range ids {
		id := raw.(string)
		var emailIDs []string
		for _, e := range s.Emails {
			if e.ThreadID == id {
				emailIDs = append(emailIDs, e.ID)
			}
		}
		if len(emailIDs) == 0 {
			notFound = append(notFound, id)
			continue
		}
		list = append(list, map[string]any{"id": id, "emailIds": emailIDs})
	}
	return map[string]any{"accountId": AccountID, "state": "t1", "list": list, "notFound": notFound}
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// MustClient returns a jmap.Client for sessionURL or fails the test.
func MustClient(t testing.TB, sessionURL, username, password string) *jmap.Client {
	t.Helper()
	c, err := jmap.NewClient(sessionURL, "", username, password)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
