package jmap

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoWriteMethodsInSource greps every non-test Go file of the module for
// references to JMAP methods or endpoints that could change server state.
func TestNoWriteMethodsInSource(t *testing.T) {
	forbidden := []string{"/set", "/copy", "/import", "emailsubmission", "upload"}
	root := filepath.Join("..", "..")
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		src := strings.ToLower(string(b))
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Errorf("%s references %q", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 5 {
		t.Fatalf("only scanned %d files; is the module root right?", scanned)
	}
}

// TestAllowlistIsReadOnly checks that only /get and /query methods are allowed.
func TestAllowlistIsReadOnly(t *testing.T) {
	for m, ok := range readOnlyMethods {
		if ok && !strings.HasSuffix(m, "/get") && !strings.HasSuffix(m, "/query") && !strings.HasSuffix(m, "/changes") {
			t.Errorf("non read-only method in allowlist: %s", m)
		}
	}
}

func TestCallRefusesUnlistedMethod(t *testing.T) {
	c := &Client{session: &session{apiURL: "http://127.0.0.1:1/", accountID: "a"}}
	_, err := c.call(t.Context(), invocation{name: "Email/" + "changes", id: "x", args: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v", err)
	}
}
