package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIEndToEnd(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(401)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			fmt.Fprint(w, `{"id":7}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			n++
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"token":"ghs_cli%d","expires_at":%q}`, n, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case r.URL.Path == "/app":
			fmt.Fprint(w, `{"name":"CLI App"}`)
		default:
			fmt.Fprint(w, `[]`)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kp := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	t.Setenv("GHAPP_TOKEN_HOME", dir)
	t.Setenv("GHAPP_APP_ID", "1")
	t.Setenv("GHAPP_PRIVATE_KEY_PATH", kp)
	t.Setenv("GHAPP_API_URL", srv.URL)

	var out, errb bytes.Buffer
	if code := run([]string{"token", "acme/widgets"}, strings.NewReader(""), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "ghs_cli1" {
		t.Fatalf("token: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	out.Reset()
	in := "protocol=https\nhost=github.com\npath=acme/widgets.git\n\n"
	if code := run([]string{"credential", "get"}, strings.NewReader(in), &out, &errb); code != 0 || !strings.Contains(out.String(), "password=ghs_cli1") {
		t.Fatalf("credential get (cached): %q %q", out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"status"}, strings.NewReader(""), &out, &errb); code != 0 || !strings.Contains(out.String(), "CLI App") || strings.Contains(out.String(), "ghs_cli1") {
		t.Fatalf("status must work and mask tokens: %q", out.String())
	}
	if code := run([]string{"token", "bad/a/b"}, strings.NewReader(""), &out, &errb); code == 0 {
		t.Fatal("bad scope must fail")
	}
	if code := run([]string{"nonsense"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatal("unknown command must exit 2")
	}
	out.Reset()
	if code := run([]string{"daemon", "--once", "--owner", "acme", "--out", filepath.Join(dir, "tok")}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("daemon once: %q", errb.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "tok"))
	if strings.TrimSpace(string(b)) != "ghs_cli2" || strings.Contains(out.String(), "ghs_cli") {
		t.Fatalf("daemon output file %q log %q", b, out.String())
	}
}
