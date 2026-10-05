// Package logsafe turns errors into log attributes without leaking full URLs,
// query strings or text supplied by upstream servers.
package logsafe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// StatusError is implemented by errors that carry an upstream HTTP status.
type StatusError interface {
	error
	HTTPStatus() int
}

// OpError labels an error with a fixed operation name chosen by our code.
type OpError struct {
	Op  string
	Err error
}

func (e *OpError) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *OpError) Unwrap() error { return e.Err }

// Wrap labels err with op (a constant string, never derived from input).
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &OpError{Op: op, Err: err}
}

// Status is a plain upstream-status error.
type Status struct {
	Op   string
	Code int
}

func (e *Status) Error() string   { return e.Op + ": unexpected HTTP status" }
func (e *Status) HTTPStatus() int { return e.Code }

// ErrRefused marks requests our own URL policy refused (e.g. a redirect).
var ErrRefused = errors.New("refused by URL policy")

// Attrs describes err as slog key/value pairs: the operation, a coarse
// error kind, the HTTP status if any, and the origin (scheme://host[:port])
// of a failed request. It never includes err.Error(), paths or queries.
func Attrs(err error) []any {
	var attrs []any
	var op *OpError
	if errors.As(err, &op) {
		attrs = append(attrs, "op", op.Op)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		attrs = append(attrs, "origin", Origin(ue.URL))
	}
	var se StatusError
	if errors.As(err, &se) {
		attrs = append(attrs, "http_status", se.HTTPStatus())
	}
	return append(attrs, "kind", Kind(err))
}

// Kind classifies err coarsely.
func Kind(err error) string {
	var (
		dnsErr  *net.DNSError
		netErr  net.Error
		certErr *tls.CertificateVerificationError
		unkAuth x509.UnknownAuthorityError
		hostErr x509.HostnameError
		recErr  tls.RecordHeaderError
		synErr  *json.SyntaxError
		typErr  *json.UnmarshalTypeError
		se      StatusError
	)
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrRefused):
		return "refused_by_policy"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certErr), errors.As(err, &unkAuth), errors.As(err, &hostErr), errors.As(err, &recErr):
		return "tls"
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return "connection"
	case errors.As(err, &synErr), errors.As(err, &typErr), errors.Is(err, io.ErrUnexpectedEOF):
		return "decode"
	case errors.As(err, &se):
		return "http_status"
	case errors.As(err, &netErr):
		return "network"
	}
	return "error"
}

// Origin returns scheme://host[:port] of raw, or "invalid" if it does not parse.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}
