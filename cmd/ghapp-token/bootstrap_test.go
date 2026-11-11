package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBootstrapFreshMachine(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app" {
			fmt.Fprint(w, `{"name":"Boot App"}`)
			return
		}
		if r.URL.Path == "/app/installations" {
			fmt.Fprint(w, `[{"id":3,"account":{"login":"acme"},"repository_selection":"all"}]`)
			return
		}
		w.WriteHeader(404)
	}))
	defer gh.Close()

	dir := t.TempDir()
	gitcfg := filepath.Join(dir, "gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", gitcfg) // never touch the real ~/.gitconfig
	t.Setenv("GHAPP_TOKEN_HOME", filepath.Join(dir, "home"))
	t.Setenv("GHAPP_API_URL", gh.URL)
	cfgPath := filepath.Join(dir, "home", "config.json")

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Bad key is rejected before anything is written.
	var out bytes.Buffer
	err := bootstrap(context.Background(), cfgPath, bootstrapOpts{AppID: "1", KeyPEM: []byte("not a key"), InstallGit: true}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "valid RSA private key") {
		t.Fatalf("expected invalid key error, got %v", err)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatal("config must not be saved on failure")
	}

	// Full bootstrap from pasted key: key stored securely, config saved, git helper registered.
	out.Reset()
	err = bootstrap(context.Background(), cfgPath, bootstrapOpts{AppID: "1", KeyPEM: keyPEM, InstallGit: true}, &out, &out)
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), `"Boot App"`) || strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatalf("unexpected output: %s", out.String())
	}
	kp := filepath.Join(dir, "home", importedKeyName)
	fi, err := os.Stat(kp)
	if err != nil {
		t.Fatal("key not stored:", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("stored key must be owner-only, got %o", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(raw), "PRIVATE KEY") || !strings.Contains(string(raw), importedKeyName) {
		t.Fatalf("config should hold only the key path: %s", raw)
	}
	gc, _ := exec.Command("git", "config", "--global", "--get-all", "credential.https://github.com.helper").Output()
	if !strings.Contains(string(gc), "credential") {
		t.Fatalf("git helper not registered: %q", gc)
	}
	if !gitHelperEnabled("github.com") {
		t.Fatal("gitHelperEnabled should report true")
	}

	// CLI path: --copy-key from an existing world-readable file, no git registration.
	src := filepath.Join(dir, "src.pem")
	_ = os.WriteFile(src, keyPEM, 0o644)
	os.Remove(kp)
	out.Reset()
	err = cmdBootstrap(context.Background(), cfgPath, []string{"--app-id", "2", "--key", src, "--copy-key", "--no-git"}, strings.NewReader(""), &out, &out)
	if err != nil {
		t.Fatalf("cmdBootstrap: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Skipped git helper") {
		t.Fatal("--no-git ignored")
	}
	if _, err := os.Stat(kp); err != nil {
		t.Fatal("--copy-key did not copy:", err)
	}

	// --key-stdin
	os.Remove(kp)
	out.Reset()
	err = cmdBootstrap(context.Background(), cfgPath, []string{"--app-id", "3", "--key-stdin", "--no-git"}, bytes.NewReader(keyPEM), &out, &out)
	if err != nil {
		t.Fatalf("key-stdin: %v\n%s", err, out.String())
	}
	if _, err := os.Stat(kp); err != nil {
		t.Fatal("--key-stdin did not store key:", err)
	}

	// Host with a scheme is rejected.
	if err := bootstrap(context.Background(), cfgPath, bootstrapOpts{Host: "https://evil/"}, &out, &out); err == nil {
		t.Fatal("bad host must be rejected")
	}
}

func TestUIBootstrapValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHAPP_TOKEN_HOME", dir)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	h := newUIHandler(filepath.Join(dir, "config.json"), "k", 1234)
	srv := httptest.NewServer(h)
	defer srv.Close()
	// Repo without destination folder is refused before any work happens.
	req, _ := http.NewRequest("POST", srv.URL+"/api/bootstrap", strings.NewReader(`{"app_id":"1","repo":"a/b"}`))
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-UI-Key", "k")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}
