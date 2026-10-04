// Package urlpolicy decides which URLs this server may talk to: https
// everywhere, plain http only to loopback hosts (local deployments), and
// never URLs carrying credentials or fragments.
package urlpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Check returns an error unless u is an absolute https URL, or an http URL
// whose host is loopback (127.0.0.0/8, ::1 or localhost). URLs with userinfo
// or a fragment are rejected.
func Check(u *url.URL) error {
	if u == nil || u.Host == "" || u.Opaque != "" {
		return errors.New("must be an absolute URL")
	}
	if u.User != nil {
		return errors.New("must not contain credentials")
	}
	if u.Fragment != "" || strings.Contains(u.String(), "#") {
		return errors.New("must not contain a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if IsLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("must use https (http is only allowed to loopback hosts, not %q)", u.Hostname())
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

// Parse parses s and applies Check.
func Parse(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("is not a valid URL")
	}
	if err := Check(u); err != nil {
		return nil, err
	}
	return u, nil
}

// IsLoopback reports whether host (without port) is localhost or a loopback IP.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Origin returns the normalised scheme://host[:port] of u, omitting the
// default port.
func Origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}
