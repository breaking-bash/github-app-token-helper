package ghapp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recorded struct {
	Method, Path string
	Body         map[string]any
}

// mockGitHub is a fake GitHub API that validates app JWTs.
type mockGitHub struct {
	*httptest.Server
	key      *rsa.PrivateKey
	clock    *fakeClock
	mu       sync.Mutex
	reqs     []recorded
	mints    int
	fail5xx  int              // number of upcoming token requests to fail with 500
	installs map[string]int64 // "owner" or "owner/repo" -> installation id
}

func newMock(t *testing.T) *mockGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockGitHub{key: key, clock: newClock(), installs: map[string]int64{"acme": 1, "acme/widgets": 1, "bob": 2}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

func (m *mockGitHub) client() *Client {
	return &Client{BaseURL: m.URL, AppID: "12345", Key: m.key, Now: m.clock.Now, RetryDelay: time.Millisecond}
}

func (m *mockGitHub) manager(cache Cache) *Manager {
	return &Manager{Client: m.client(), Cache: cache, AppID: "12345", Now: m.clock.Now, Perms: map[string]string{"contents": "read"}}
}

func (m *mockGitHub) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.mints }
func (m *mockGitHub) last() recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reqs[len(m.reqs)-1]
}

func (m *mockGitHub) verifyJWT(h string) error {
	tok := strings.TrimPrefix(h, "Bearer ")
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return fmt.Errorf("not a JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err := rsa.VerifyPKCS1v15(&m.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	cb, _ := base64.RawURLEncoding.DecodeString(p[1])
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	_ = json.Unmarshal(cb, &c)
	now := m.clock.Now().Unix()
	if c.Iss != "12345" || c.Exp <= now || c.Exp-now > 600 || c.Iat > now {
		return fmt.Errorf("bad claims %+v", c)
	}
	return nil
}

func (m *mockGitHub) handle(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if err := m.verifyJWT(r.Header.Get("Authorization")); err != nil {
		reply(401, map[string]string{"message": "Bad credentials"})
		return
	}
	rec := recorded{Method: r.Method, Path: r.URL.Path}
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			_ = json.Unmarshal(b, &rec.Body)
		}
	}
	m.mu.Lock()
	m.reqs = append(m.reqs, rec)
	m.mu.Unlock()

	path := r.URL.Path
	switch {
	case path == "/app":
		reply(200, map[string]string{"name": "Test App"})
	case path == "/app/installations":
		reply(200, []map[string]any{
			{"id": 1, "account": map[string]string{"login": "acme"}, "repository_selection": "all"},
			{"id": 2, "account": map[string]string{"login": "bob"}, "repository_selection": "selected"},
		})
	case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/installation"):
		k := strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/installation")
		if id, ok := m.installs[k]; ok {
			reply(200, map[string]int64{"id": id})
		} else {
			reply(404, map[string]string{"message": "Not Found"})
		}
	case strings.HasPrefix(path, "/orgs/") && strings.HasSuffix(path, "/installation"):
		k := strings.TrimSuffix(strings.TrimPrefix(path, "/orgs/"), "/installation")
		if k == "acme" {
			reply(200, map[string]int64{"id": m.installs["acme"]})
		} else {
			reply(404, map[string]string{"message": "Not Found"})
		}
	case strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/installation"):
		k := strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/installation")
		if id, ok := m.installs[k]; ok {
			reply(200, map[string]int64{"id": id})
		} else {
			reply(404, map[string]string{"message": "Not Found"})
		}
	case strings.HasPrefix(path, "/app/installations/") && strings.HasSuffix(path, "/access_tokens"):
		m.mu.Lock()
		if m.fail5xx > 0 {
			m.fail5xx--
			m.mu.Unlock()
			reply(500, map[string]string{"message": "boom"})
			return
		}
		m.mints++
		n := m.mints
		m.mu.Unlock()
		reply(201, map[string]any{
			"token":      fmt.Sprintf("ghs_token%d", n),
			"expires_at": m.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	default:
		reply(404, map[string]string{"message": "Not Found"})
	}
}

func pemPKCS1(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}
