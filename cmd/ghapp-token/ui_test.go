package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func uiCall(t *testing.T, base, method, path, key, host, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("X-UI-Key", key)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestUIServer(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app":
			fmt.Fprint(w, `{"name":"UI App"}`)
		case r.URL.Path == "/app/installations":
			fmt.Fprint(w, `[{"id":3,"account":{"login":"acme"},"repository_selection":"all"}]`)
		case strings.HasSuffix(r.URL.Path, "/installation"):
			fmt.Fprint(w, `{"id":3}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"token":"ghs_uitoken_secret","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"Not Found"}`)
		}
	}))
	defer gh.Close()

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kp := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	t.Setenv("GHAPP_TOKEN_HOME", dir)
	t.Setenv("GHAPP_API_URL", gh.URL)

	ui := httptest.NewUnstartedServer(nil)
	port := ui.Listener.Addr().(*net.TCPAddr).Port
	ui.Config.Handler = newUIHandler(filepath.Join(dir, "config.json"), "sekret", port)
	ui.Start()
	defer ui.Close()
	base := ui.URL
	const k = "sekret"

	// Page is served, API is protected.
	if code, body := uiCall(t, base, "GET", "/", "", "", ""); code != 200 || !strings.Contains(body, "GitHub App Token Helper") {
		t.Fatalf("index: %d", code)
	}
	if code, _ := uiCall(t, base, "GET", "/api/status", "", "", ""); code != 403 {
		t.Fatalf("missing key must be 403, got %d", code)
	}
	if code, _ := uiCall(t, base, "GET", "/api/status", "wrong", "", ""); code != 403 {
		t.Fatal("wrong key must be 403")
	}
	if code, _ := uiCall(t, base, "GET", "/api/status", k, "evil.example.com", ""); code != 403 {
		t.Fatal("non-loopback Host (DNS rebinding) must be 403")
	}
	if code, _ := uiCall(t, base, "POST", "/api/status", k, "", "{}"); code != 405 {
		t.Fatal("wrong method must be 405")
	}

	// Unconfigured status.
	if code, body := uiCall(t, base, "GET", "/api/status", k, "", ""); code != 200 || strings.Contains(body, "app_name") {
		t.Fatalf("unconfigured status: %d %s", code, body)
	}

	// Bad key path is rejected and not saved.
	if code, _ := uiCall(t, base, "POST", "/api/config", k, "", `{"host":"github.com","app_id":"1","key_path":"`+filepath.ToSlash(filepath.Join(dir, "missing.pem"))+`"}`); code != 400 {
		t.Fatal("missing key must be rejected")
	}
	if code, _ := uiCall(t, base, "POST", "/api/config", k, "", `{"host":"https://evil/","app_id":"1","key_path":"x"}`); code != 400 {
		t.Fatal("host with scheme must be rejected")
	}

	// Valid config.
	cfgBody := `{"host":"github.com","app_id":"1","key_path":"` + strings.ReplaceAll(kp, `\`, `\\`) + `","write":false}`
	if code, body := uiCall(t, base, "POST", "/api/config", k, "", cfgBody); code != 200 || !strings.Contains(body, "UI App") {
		t.Fatalf("save: %d %s", code, body)
	}

	// Token endpoint returns the token; status afterwards masks it.
	if code, body := uiCall(t, base, "POST", "/api/token", k, "", `{"scope":"acme/widgets"}`); code != 200 || !strings.Contains(body, "ghs_uitoken_secret") {
		t.Fatalf("token: %d %s", code, body)
	}
	if code, body := uiCall(t, base, "POST", "/api/token", k, "", `{"scope":"a/b/c"}`); code != 400 {
		t.Fatalf("bad scope: %d %s", code, body)
	}
	code, body := uiCall(t, base, "GET", "/api/status", k, "", "")
	if code != 200 || !strings.Contains(body, `"app_name":"UI App"`) || !strings.Contains(body, "acme") || strings.Contains(body, "uitoken_secret") {
		t.Fatalf("status after config must show app and mask tokens: %s", body)
	}
	if code, body := uiCall(t, base, "POST", "/api/refresh", k, "", "{}"); code != 200 || !strings.Contains(body, `"count":1`) {
		t.Fatalf("refresh: %d %s", code, body)
	}

	// Clone validation (no network/git call reached).
	for _, b := range []string{`{"repo":"","dir":"x"}`, `{"repo":"acme/widgets","dir":""}`, `{"repo":"acme","dir":"x"}`, `{"repo":"acme/widgets","dir":"--upload-pack=evil"}`} {
		if code, _ := uiCall(t, base, "POST", "/api/clone", k, "", b); code != 400 {
			t.Fatalf("clone %s must be rejected", b)
		}
	}
	// Config file never contains tokens, only the key path.
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if strings.Contains(string(raw), "ghs_") || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("config must not contain secrets")
	}
}
