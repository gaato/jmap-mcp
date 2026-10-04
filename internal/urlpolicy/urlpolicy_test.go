package urlpolicy

import (
	"net/url"
	"testing"
)

func TestParse(t *testing.T) {
	ok := []string{
		"https://id.example.net/oauth2/openid/x",
		"http://127.0.0.1:8080/x",
		"http://127.1.2.3/",
		"http://[::1]:1/",
		"http://localhost/x",
		"http://LOCALHOST:9/",
	}
	bad := []string{
		"http://id.example.net/",
		"http://10.0.0.1/",
		"http://127.0.0.1.example.net/",
		"https://user:pw@id.example.net/",
		"https://id.example.net/#frag",
		"ftp://id.example.net/",
		"id.example.net",
		"/relative",
		"https:opaque",
	}
	for _, s := range ok {
		if _, err := Parse(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
}

func TestOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Mail.Example.net:443/.well-known/jmap": "https://mail.example.net",
		"https://mail.example.net:8443/x":               "https://mail.example.net:8443",
		"http://127.0.0.1:80/":                          "http://127.0.0.1",
		"http://[::1]:8080/":                            "http://[::1]:8080",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		if got := Origin(u); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
