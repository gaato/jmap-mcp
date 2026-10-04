package jmap

import (
	"context"
	"encoding/json"
	"fmt"
)

// Mailbox is a subset of the RFC 8621 Mailbox object.
type Mailbox struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ParentID     string `json:"parentId,omitempty"`
	Role         string `json:"role,omitempty"`
	TotalEmails  int    `json:"totalEmails"`
	UnreadEmails int    `json:"unreadEmails"`
}

// Address is an RFC 8621 EmailAddress.
type Address struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

// EmailSummary holds the header-level properties used in listings.
type EmailSummary struct {
	ID            string          `json:"id"`
	ThreadID      string          `json:"threadId"`
	MailboxIDs    map[string]bool `json:"mailboxIds"`
	Keywords      map[string]bool `json:"keywords"`
	From          []Address       `json:"from"`
	To            []Address       `json:"to"`
	Cc            []Address       `json:"cc"`
	Subject       string          `json:"subject"`
	ReceivedAt    string          `json:"receivedAt"`
	SentAt        string          `json:"sentAt"`
	Preview       string          `json:"preview"`
	MessageID     []string        `json:"messageId"`
	HasAttachment bool            `json:"hasAttachment"`
}

// BodyPart is a subset of EmailBodyPart.
type BodyPart struct {
	PartID string `json:"partId"`
	Type   string `json:"type"`
}

// BodyValue is an EmailBodyValue.
type BodyValue struct {
	Value             string `json:"value"`
	IsTruncated       bool   `json:"isTruncated"`
	IsEncodingProblem bool   `json:"isEncodingProblem"`
}

// Email is a summary plus the text body parts and their decoded values.
type Email struct {
	EmailSummary
	TextBody   []BodyPart           `json:"textBody"`
	BodyValues map[string]BodyValue `json:"bodyValues"`
}

var summaryProperties = []string{
	"id", "threadId", "mailboxIds", "keywords", "from", "to", "cc", "subject",
	"receivedAt", "sentAt", "preview", "messageId", "hasAttachment",
}

// EmailFilter is an RFC 8621 Email/query FilterCondition (subset).
type EmailFilter struct {
	Text      string `json:"text,omitempty"`
	InMailbox string `json:"inMailbox,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	After     string `json:"after,omitempty"`  // UTCDate, inclusive
	Before    string `json:"before,omitempty"` // UTCDate, exclusive
}

// Mailboxes returns all mailboxes of the account.
func (c *Client) Mailboxes(ctx context.Context) ([]Mailbox, error) {
	res, err := c.call(ctx, invocation{name: "Mailbox/get", id: "m", args: map[string]any{
		"ids":        nil,
		"properties": []string{"id", "name", "parentId", "role", "totalEmails", "unreadEmails"},
	}})
	if err != nil {
		return nil, err
	}
	var out struct {
		List []Mailbox `json:"list"`
	}
	if err := json.Unmarshal(res["m"], &out); err != nil {
		return nil, fmt.Errorf("jmap: decode Mailbox/get: %w", err)
	}
	return out.List, nil
}

// SearchEmails runs Email/query (newest first) and fetches summaries of the
// matches in the same request using a result reference.
func (c *Client) SearchEmails(ctx context.Context, f EmailFilter, limit int) ([]EmailSummary, int, error) {
	res, err := c.call(ctx,
		invocation{name: "Email/query", id: "q", args: map[string]any{
			"filter":         f,
			"sort":           []map[string]any{{"property": "receivedAt", "isAscending": false}},
			"limit":          limit,
			"calculateTotal": true,
		}},
		invocation{name: "Email/get", id: "g", args: map[string]any{
			"#ids":       map[string]string{"resultOf": "q", "name": "Email/query", "path": "/ids"},
			"properties": summaryProperties,
		}},
	)
	if err != nil {
		return nil, 0, err
	}
	var q struct {
		IDs   []string `json:"ids"`
		Total int      `json:"total"`
	}
	if err := json.Unmarshal(res["q"], &q); err != nil {
		return nil, 0, fmt.Errorf("jmap: decode Email/query: %w", err)
	}
	list, err := decodeEmails[EmailSummary](res["g"])
	if err != nil {
		return nil, 0, err
	}
	return orderByIDs(list, q.IDs), q.Total, nil
}

// GetEmail fetches one email with its text body. maxBodyBytes bounds the
// size of each decoded body value returned by the server.
func (c *Client) GetEmail(ctx context.Context, id string, maxBodyBytes int) (*Email, error) {
	res, err := c.call(ctx, invocation{name: "Email/get", id: "g", args: map[string]any{
		"ids":                 []string{id},
		"properties":          append(append([]string{}, summaryProperties...), "textBody", "bodyValues"),
		"bodyProperties":      []string{"partId", "type"},
		"fetchTextBodyValues": true,
		"maxBodyValueBytes":   maxBodyBytes,
	}})
	if err != nil {
		return nil, err
	}
	list, err := decodeEmails[Email](res["g"])
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, &MethodError{Method: "Email/get", Type: "notFound", Description: "no such email"}
	}
	return &list[0], nil
}

// GetThread returns summaries of the emails in a thread, oldest first,
// limited to the newest limit emails.
func (c *Client) GetThread(ctx context.Context, threadID string, limit int) ([]EmailSummary, int, error) {
	res, err := c.call(ctx, invocation{name: "Thread/get", id: "t", args: map[string]any{
		"ids": []string{threadID},
	}})
	if err != nil {
		return nil, 0, err
	}
	var t struct {
		List []struct {
			EmailIDs []string `json:"emailIds"`
		} `json:"list"`
	}
	if err := json.Unmarshal(res["t"], &t); err != nil {
		return nil, 0, fmt.Errorf("jmap: decode Thread/get: %w", err)
	}
	if len(t.List) == 0 {
		return nil, 0, &MethodError{Method: "Thread/get", Type: "notFound", Description: "no such thread"}
	}
	ids := t.List[0].EmailIDs // sorted by receivedAt, oldest first (RFC 8621 section 3)
	total := len(ids)
	if len(ids) > limit {
		ids = ids[len(ids)-limit:]
	}
	if len(ids) == 0 {
		return nil, 0, nil
	}
	res, err = c.call(ctx, invocation{name: "Email/get", id: "g", args: map[string]any{
		"ids":        ids,
		"properties": summaryProperties,
	}})
	if err != nil {
		return nil, 0, err
	}
	list, err := decodeEmails[EmailSummary](res["g"])
	if err != nil {
		return nil, 0, err
	}
	return orderByIDs(list, ids), total, nil
}

func decodeEmails[T any](raw json.RawMessage) ([]T, error) {
	var out struct {
		List []T `json:"list"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("jmap: decode Email/get: %w", err)
	}
	return out.List, nil
}

type identified interface{ getID() string }

func (e EmailSummary) getID() string { return e.ID }

// orderByIDs returns list in the order given by ids (Email/get does not
// guarantee order).
func orderByIDs[T identified](list []T, ids []string) []T {
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}
	out := make([]T, 0, len(list))
	placed := make([]*T, len(ids))
	for i := range list {
		if p, ok := pos[list[i].getID()]; ok {
			placed[p] = &list[i]
		}
	}
	for _, p := range placed {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}
