// Package jmap is a minimal, read-only JMAP (RFC 8620/8621) client.
//
// It is read-only by construction: every method call goes through call(),
// which refuses any method name outside readOnlyMethods. The package has no
// code paths for state-changing methods, blob transfer or submission.
package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	capCore = "urn:ietf:params:jmap:core"
	capMail = "urn:ietf:params:jmap:mail"
)

// readOnlyMethods is the complete set of JMAP methods this client may invoke.
var readOnlyMethods = map[string]bool{
	"Mailbox/get": true,
	"Email/query": true,
	"Email/get":   true,
	"Thread/get":  true,
}

// maxResponseBytes caps how much of a JMAP response is read into memory.
const maxResponseBytes = 32 << 20

// ErrUnauthorized means the JMAP server rejected the configured credentials.
var ErrUnauthorized = errors.New("jmap: credentials rejected by server")

// RequestError is a request-level failure (RFC 8620 section 3.6.1) or an
// unexpected HTTP status.
type RequestError struct {
	Status int
	Type   string
	Detail string
}

func (e *RequestError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("jmap: request failed (HTTP %d): %s %s", e.Status, e.Type, e.Detail)
	}
	return fmt.Sprintf("jmap: request failed (HTTP %d)", e.Status)
}

// MethodError is a method-level error response (RFC 8620 section 3.6.2).
type MethodError struct {
	Method      string
	Type        string
	Description string
}

func (e *MethodError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("jmap: %s failed: %s (%s)", e.Method, e.Type, e.Description)
	}
	return fmt.Sprintf("jmap: %s failed: %s", e.Method, e.Type)
}

// Client talks to a single JMAP account using HTTP Basic authentication.
type Client struct {
	sessionURL string
	username   string
	password   string
	hc         *http.Client

	mu      sync.Mutex
	session *session
}

type session struct {
	apiURL    string
	accountID string
	state     string
}

// NewClient returns a client. hc may be nil.
func NewClient(sessionURL, username, password string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{sessionURL: sessionURL, username: username, password: password, hc: hc}
}

func (c *Client) getSession(ctx context.Context) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.username, c.password)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap: fetch session: %w", err)
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return nil, err
	}
	var doc struct {
		APIURL          string            `json:"apiUrl"`
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
		State           string            `json:"state"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jmap: decode session: %w", err)
	}
	acct := doc.PrimaryAccounts[capMail]
	if acct == "" || doc.APIURL == "" {
		return nil, errors.New("jmap: session has no apiUrl or primary mail account")
	}
	// apiUrl may be relative; resolve it against the URL the session came from.
	api, err := resp.Request.URL.Parse(doc.APIURL)
	if err != nil {
		return nil, fmt.Errorf("jmap: bad apiUrl: %w", err)
	}
	c.session = &session{apiURL: api.String(), accountID: acct, state: doc.State}
	return c.session, nil
}

func (c *Client) invalidateSession() {
	c.mu.Lock()
	c.session = nil
	c.mu.Unlock()
}

func statusError(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	}
	re := &RequestError{Status: resp.StatusCode}
	var problem struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&problem) == nil {
		re.Type, re.Detail = problem.Type, problem.Detail
	}
	return re
}

// invocation is one JMAP method call; it marshals as [name, args, callId].
type invocation struct {
	name string
	args map[string]any
	id   string
}

func (i invocation) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{i.name, i.args, i.id})
}

type response struct {
	name string
	args json.RawMessage
	id   string
}

func (r *response) UnmarshalJSON(b []byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(b, &parts); err != nil {
		return err
	}
	if len(parts) != 3 {
		return errors.New("jmap: malformed method response")
	}
	if err := json.Unmarshal(parts[0], &r.name); err != nil {
		return err
	}
	r.args = parts[1]
	return json.Unmarshal(parts[2], &r.id)
}

// call sends the invocations in one request and returns the responses keyed
// by call id. The accountId is filled in automatically. A method error in any
// response is returned as *MethodError.
func (c *Client) call(ctx context.Context, calls ...invocation) (map[string]json.RawMessage, error) {
	s, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	for _, inv := range calls {
		if !readOnlyMethods[inv.name] {
			return nil, fmt.Errorf("jmap: method %q is not allowed (read-only client)", inv.name)
		}
		inv.args["accountId"] = s.accountID
	}
	body, err := json.Marshal(map[string]any{
		"using":       []string{capCore, capMail},
		"methodCalls": calls,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.username, c.password)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap: request: %w", err)
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			c.invalidateSession()
		}
		return nil, err
	}
	var out struct {
		MethodResponses []response `json:"methodResponses"`
		SessionState    string     `json:"sessionState"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("jmap: decode response: %w", err)
	}
	if out.SessionState != "" && out.SessionState != s.state {
		c.invalidateSession() // refetch the session (apiUrl, accounts) next time
	}
	res := make(map[string]json.RawMessage, len(out.MethodResponses))
	for _, r := range out.MethodResponses {
		if r.name == "error" {
			var e struct {
				Type        string `json:"type"`
				Description string `json:"description"`
			}
			_ = json.Unmarshal(r.args, &e)
			method := r.id
			for _, inv := range calls {
				if inv.id == r.id {
					method = inv.name
				}
			}
			if e.Type == "accountNotFound" {
				c.invalidateSession()
			}
			return nil, &MethodError{Method: method, Type: e.Type, Description: e.Description}
		}
		res[r.id] = r.args
	}
	for _, inv := range calls {
		if _, ok := res[inv.id]; !ok {
			return nil, fmt.Errorf("jmap: no response for %s", inv.name)
		}
	}
	return res, nil
}

// EmailURL returns a citation URL for an email: an RFC 2392 "mid:" URL when
// the message has a Message-ID. No public web URL exists for a mailbox item.
func EmailURL(messageIDs []string) string {
	if len(messageIDs) == 0 || messageIDs[0] == "" {
		return ""
	}
	return "mid:" + url.PathEscape(messageIDs[0])
}
