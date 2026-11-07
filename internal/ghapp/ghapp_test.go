package ghapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWTSignAndClaims(t *testing.T) {
	m := newMock(t)
	now := m.clock.Now()
	tok, err := SignJWT(m.key, "12345", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.verifyJWT("Bearer " + tok); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(hb), `"RS256"`) {
		t.Fatalf("header %s", hb)
	}
	var c struct{ Iat, Exp int64 }
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &c)
	if c.Exp-c.Iat > 600 {
		t.Fatalf("lifetime %ds exceeds GitHub's 10 minute maximum", c.Exp-c.Iat)
	}
	if c.Iat >= now.Unix() {
		t.Fatal("iat must be backdated for clock skew")
	}
	if _, err := SignJWT(m.key, "", now); err == nil {
		t.Fatal("empty app id must fail")
	}
}

func TestParsePrivateKey(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ParsePrivateKey(pemPKCS1(k)); err != nil {
		t.Fatalf("pkcs1: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	for _, bad := range []string{"", "garbage", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"} {
		if _, err := ParsePrivateKey([]byte(bad)); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestTokenCachedWithinTenMinutesThenRefreshed(t *testing.T) {
	m := newMock(t)
	mgr := m.manager(&MemCache{})
	ctx := context.Background()
	s := Scope{Owner: "acme", Repo: "widgets"}

	t1, err := mgr.Token(ctx, s, false)
	if err != nil || t1.Value != "ghs_token1" {
		t.Fatalf("first: %v %v", t1, err)
	}
	m.clock.Advance(9*time.Minute + 59*time.Second)
	t2, _ := mgr.Token(ctx, s, false)
	if t2.Value != "ghs_token1" || m.count() != 1 {
		t.Fatalf("expected cached token before 10 minutes, got %s (mints=%d)", t2.Value, m.count())
	}
	m.clock.Advance(2 * time.Second)
	t3, _ := mgr.Token(ctx, s, false)
	if t3.Value != "ghs_token2" || m.count() != 2 {
		t.Fatalf("expected refresh after 10 minutes, got %s", t3.Value)
	}
}

func TestExpiredOrNearExpiryTokenIsReplaced(t *testing.T) {
	m := newMock(t)
	cache := &MemCache{}
	mgr := m.manager(cache)
	mgr.MaxAge = 24 * time.Hour // isolate the expiry rule
	s := Scope{Owner: "acme", Repo: "widgets"}
	_, _ = mgr.Token(context.Background(), s, false)
	m.clock.Advance(56 * time.Minute) // <5 minutes of validity left
	tok, _ := mgr.Token(context.Background(), s, false)
	if tok.Value != "ghs_token2" {
		t.Fatalf("near-expiry token must be replaced, got %s", tok.Value)
	}
}

func TestForceAndScopes(t *testing.T) {
	m := newMock(t)
	mgr := m.manager(&MemCache{})
	ctx := context.Background()
	_, _ = mgr.Token(ctx, Scope{Owner: "acme", Repo: "widgets"}, false)
	req := m.last()
	repos, _ := req.Body["repositories"].([]any)
	perms, _ := req.Body["permissions"].(map[string]any)
	if len(repos) != 1 || repos[0] != "widgets" || perms["contents"] != "read" {
		t.Fatalf("repo-scoped body wrong: %+v", req.Body)
	}
	if req.Path != "/app/installations/1/access_tokens" {
		t.Fatalf("path %s", req.Path)
	}
	// Installation-wide: no repositories list; falls back from /orgs to /users for a user account.
	_, err := mgr.Token(ctx, Scope{Owner: "bob"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := m.last().Body["repositories"]; has || m.last().Path != "/app/installations/2/access_tokens" {
		t.Fatalf("installation-wide request wrong: %+v", m.last())
	}
	before := m.count()
	_, _ = mgr.Token(ctx, Scope{Owner: "bob"}, true)
	if m.count() != before+1 {
		t.Fatal("force must mint a new token")
	}
}

func TestErrors(t *testing.T) {
	m := newMock(t)
	mgr := m.manager(&MemCache{})
	ctx := context.Background()

	_, err := mgr.Token(ctx, Scope{Owner: "acme", Repo: "not-installed"}, false)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("want helpful 404, got %v", err)
	}

	// Wrong key => 401 from the mock, and the error must not leak the JWT.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := m.client()
	bad.Key = other
	_, err = bad.AppName(ctx)
	if !errors.As(err, &ae) || ae.Status != 401 || strings.Contains(err.Error(), "eyJ") {
		t.Fatalf("want clean 401, got %v", err)
	}

	// Transient 500s are retried.
	m.mu.Lock()
	m.fail5xx = 2
	m.mu.Unlock()
	tok, err := mgr.Token(ctx, Scope{Owner: "acme", Repo: "widgets"}, false)
	if err != nil || tok.Value == "" {
		t.Fatalf("retry failed: %v", err)
	}
	// Persistent 500s eventually fail.
	m.mu.Lock()
	m.fail5xx = 10
	m.mu.Unlock()
	if _, err := mgr.Token(ctx, Scope{Owner: "acme", Repo: "widgets"}, true); err == nil {
		t.Fatal("expected failure after retries")
	}
	// Unreachable server.
	m.Close()
	if _, err := m.client().AppName(ctx); err == nil || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("expected clean network error, got %v", err)
	}
}

func TestCredentialHelperProtocol(t *testing.T) {
	m := newMock(t)
	mgr := m.manager(&MemCache{})
	h := &CredentialHandler{Manager: mgr, Host: "github.com"}
	ctx := context.Background()
	in := ParseCredentialInput(strings.NewReader("protocol=https\nhost=github.com\npath=acme/widgets.git\n\n"))

	var out bytes.Buffer
	if err := h.Handle(ctx, "get", in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "username=x-access-token\n") || !strings.Contains(out.String(), "password=ghs_token1\n") ||
		!strings.Contains(out.String(), "password_expiry_utc=") {
		t.Fatalf("bad output %q", out.String())
	}
	// Same token while fresh.
	out.Reset()
	_ = h.Handle(ctx, "get", in, &out)
	if !strings.Contains(out.String(), "ghs_token1") {
		t.Fatal("expected cached token")
	}
	// git reports rejection -> erase -> next get re-mints.
	if err := h.Handle(ctx, "erase", in, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = h.Handle(ctx, "get", in, &out)
	if !strings.Contains(out.String(), "ghs_token2") {
		t.Fatalf("expected new token after erase, got %q", out.String())
	}
	// store is a no-op.
	out.Reset()
	if err := h.Handle(ctx, "store", in, &out); err != nil || out.Len() != 0 {
		t.Fatal("store must be silent")
	}
	// Other hosts / protocols are ignored silently.
	for _, raw := range []string{"protocol=https\nhost=gitlab.com\npath=a/b\n", "protocol=http\nhost=github.com\npath=a/b\n", "protocol=ssh\nhost=github.com\n"} {
		out.Reset()
		if err := h.Handle(ctx, "get", ParseCredentialInput(strings.NewReader(raw)), &out); err != nil || out.Len() != 0 {
			t.Fatalf("must ignore %q", raw)
		}
	}
	if err := h.Handle(ctx, "bogus", in, &out); err == nil {
		t.Fatal("unknown op must error")
	}
	// Error is surfaced for repos without installation.
	err := h.Handle(ctx, "get", ParseCredentialInput(strings.NewReader("protocol=https\nhost=github.com\npath=acme/nope.git\n")), &out)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialNoPathAndInstallationWide(t *testing.T) {
	m := newMock(t)
	h := &CredentialHandler{Manager: m.manager(&MemCache{}), Host: "github.com"}
	in := map[string]string{"protocol": "https", "host": "github.com"}
	var out bytes.Buffer
	// Two installations and no default owner: ambiguous.
	if err := h.Handle(context.Background(), "get", in, &out); err == nil || !strings.Contains(err.Error(), "useHttpPath") {
		t.Fatalf("want ambiguity error, got %v", err)
	}
	h.DefaultOwner = "acme"
	if err := h.Handle(context.Background(), "get", in, &out); err != nil || !strings.Contains(out.String(), "password=") {
		t.Fatalf("default owner: %v", err)
	}
	h.InstallationWide = true
	out.Reset()
	_ = h.Handle(context.Background(), "get", map[string]string{"protocol": "https", "host": "github.com", "path": "acme/widgets.git"}, &out)
	if _, has := m.last().Body["repositories"]; has {
		t.Fatal("installation-wide must not scope to a repository")
	}
}

func TestScopeFromPath(t *testing.T) {
	for in, want := range map[string]Scope{
		"acme/widgets.git": {"acme", "widgets"}, "acme/widgets": {"acme", "widgets"}, "/acme/widgets.git/": {"acme", "widgets"},
	} {
		if got, ok := ScopeFromPath(in); !ok || got != want {
			t.Errorf("%q => %v %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "acme", "/", "acme/.git"} {
		if _, ok := ScopeFromPath(in); ok {
			t.Errorf("%q should not parse", in)
		}
	}
}

func TestFileCache(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	c := &FileCache{Path: filepath.Join(dir, "sub", "tokens.json"), Now: clock.Now}
	e := Entry{Token: "ghs_x", Expires: clock.Now().Add(time.Hour), MintedAt: clock.Now()}
	if err := c.Put("k", e); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Get("k"); !ok || got.Token != "ghs_x" {
		t.Fatal("roundtrip failed")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(c.Path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("cache mode %o", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(c.Path))
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %o", di.Mode().Perm())
		}
	}
	clock.Advance(2 * time.Hour)
	_ = c.Put("k2", Entry{Token: "ghs_y", Expires: clock.Now().Add(time.Hour)})
	if _, ok := c.Get("k"); ok {
		t.Fatal("expired entries must be dropped")
	}
	_ = c.Delete("k2")
	if len(c.All()) != 0 {
		t.Fatal("delete failed")
	}
	_ = os.WriteFile(c.Path, []byte("{corrupt"), 0o600)
	if _, ok := c.Get("k"); ok {
		t.Fatal("corrupt cache must read as empty")
	}
	if err := c.Put("k", e); err != nil {
		t.Fatal("must recover from corrupt cache")
	}
}

func TestRefreshLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 260*time.Millisecond)
	defer cancel()
	var calls, errs int32
	RefreshLoop(ctx, 50*time.Millisecond, func(context.Context) error {
		if atomic.AddInt32(&calls, 1) == 2 {
			return errors.New("transient")
		}
		return nil
	}, func(error) { atomic.AddInt32(&errs, 1) })
	if c := atomic.LoadInt32(&calls); c < 4 || c > 7 {
		t.Fatalf("calls=%d", c)
	}
	if errs != 1 {
		t.Fatalf("loop must continue after an error and report it once, errs=%d", errs)
	}
}

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	c := &Config{AppID: "1", KeyPath: "/k.pem", Host: "ghe.example.com"}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHAPP_APP_ID", "99")
	got, err := LoadConfig(p)
	if err != nil || got.AppID != "99" || got.Host != "ghe.example.com" {
		t.Fatalf("%+v %v", got, err)
	}
	if got.API() != "https://ghe.example.com/api/v3" || got.Permissions["contents"] != "read" {
		t.Fatalf("defaults wrong: %+v", got)
	}
	if (&Config{Host: "github.com"}).API() != "https://api.github.com" {
		t.Fatal("github.com API")
	}
	if got.Interval() != 10*time.Minute {
		t.Fatal("default interval must be 10m")
	}
	if err := (&Config{}).Validate(); err == nil {
		t.Fatal("empty config must be invalid")
	}
}

func TestKeyPermissionCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission semantics")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(p, pemPKCS1(k), 0o644)
	if _, err := ReadKeyFile(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("want permission error, got %v", err)
	}
	_ = os.Chmod(p, 0o600)
	if _, err := ReadKeyFile(p); err != nil {
		t.Fatal(err)
	}
}

func TestMask(t *testing.T) {
	if got := Mask("ghs_abcdefghijklmnop"); strings.Contains(got, "efgh") {
		t.Fatalf("leaks: %s", got)
	}
	if Mask("short") != "********" {
		t.Fatal("short")
	}
}

func TestNewManagerFromConfigEndToEnd(t *testing.T) {
	m := newMock(t)
	m.clock.t = time.Now()
	dir := t.TempDir()
	t.Setenv("GHAPP_TOKEN_HOME", dir)
	kp := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(kp, pemPKCS1(m.key), 0o600)
	cfg := &Config{AppID: "12345", KeyPath: kp, Host: "github.com", APIURL: m.URL, Permissions: map[string]string{"contents": "read"}}
	mgr, err := cfg.NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := mgr.Token(context.Background(), Scope{Owner: "acme", Repo: "widgets"}, false)
	if err != nil || !strings.HasPrefix(tok.Value, "ghs_") {
		t.Fatal(err)
	}
	// A second manager (new process) reuses the file cache.
	mgr2, _ := cfg.NewManager(nil)
	tok2, _ := mgr2.Token(context.Background(), Scope{Owner: "acme", Repo: "widgets"}, false)
	if tok2.Value != tok.Value || m.count() != 1 {
		t.Fatal("file cache must be shared across processes")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if !bytes.Contains(raw, []byte(tok.Value)) {
		t.Fatal("sanity: cache holds token")
	}
}
