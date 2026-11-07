package ghapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Defaults for the refresh policy. GitHub installation tokens live 1 hour;
// we deliberately replace them after 10 minutes.
const (
	DefaultMaxAge      = 10 * time.Minute
	DefaultMinValidity = 5 * time.Minute
)

// Scope selects what a token covers. Repo == "" means the whole installation
// on Owner (all repositories the App can access there).
type Scope struct {
	Owner string
	Repo  string
}

// Key is the cache key for a scope.
func (s Scope) Key(appID string) string {
	r := s.Repo
	if r == "" {
		r = "*"
	}
	return strings.ToLower(appID + ":" + s.Owner + "/" + r)
}

// Entry is a cached token.
type Entry struct {
	Token    string    `json:"token"`
	Expires  time.Time `json:"expires_at"`
	MintedAt time.Time `json:"minted_at"`
}

// Cache stores tokens between process invocations.
type Cache interface {
	Get(key string) (Entry, bool)
	Put(key string, e Entry) error
	Delete(key string) error
	All() map[string]Entry
}

// MemCache is an in-memory Cache (also used when caching is disabled).
type MemCache struct {
	mu sync.Mutex
	m  map[string]Entry
}

func (c *MemCache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	return e, ok
}
func (c *MemCache) Put(key string, e Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]Entry{}
	}
	c.m[key] = e
	return nil
}
func (c *MemCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}
func (c *MemCache) All() map[string]Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Entry{}
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// FileCache persists tokens in a single JSON file with owner-only permissions
// (0600 file, 0700 directory). Expired entries are dropped on write.
type FileCache struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func (c *FileCache) load() map[string]Entry {
	m := map[string]Entry{}
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return m
	}
	if json.Unmarshal(b, &m) != nil {
		return map[string]Entry{} // corrupt cache is treated as empty
	}
	return m
}

func (c *FileCache) save(m map[string]Entry) error {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	for k, e := range m {
		if !e.Expires.After(now) {
			delete(m, k)
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.Path), ".tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		// Chmod is best-effort on Windows.
		_ = err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.Path)
}

func (c *FileCache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.load()[key]
	return e, ok
}
func (c *FileCache) Put(key string, e Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.load()
	m[key] = e
	return c.save(m)
}
func (c *FileCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.load()
	delete(m, key)
	return c.save(m)
}
func (c *FileCache) All() map[string]Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.load()
}

// Manager hands out tokens, reusing cached ones while they are younger than
// MaxAge and have at least MinValidity left; otherwise it mints a new one.
type Manager struct {
	Client      *Client
	Cache       Cache
	AppID       string
	MaxAge      time.Duration
	MinValidity time.Duration
	Perms       map[string]string
	Now         func() time.Time
	mu          sync.Mutex
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) fresh(e Entry) bool {
	maxAge, minValid := m.MaxAge, m.MinValidity
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	if minValid == 0 {
		minValid = DefaultMinValidity
	}
	now := m.now()
	return e.Token != "" && now.Sub(e.MintedAt) < maxAge && e.Expires.Sub(now) > minValid
}

// Token returns a valid token for the scope. If force is set the cache is bypassed.
func (m *Manager) Token(ctx context.Context, s Scope, force bool) (Token, error) {
	if s.Owner == "" {
		return Token{}, errors.New("owner is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := s.Key(m.AppID)
	if !force {
		if e, ok := m.Cache.Get(key); ok && m.fresh(e) {
			return Token{Value: e.Token, ExpiresAt: e.Expires}, nil
		}
	}
	var (
		id    int64
		err   error
		repos []string
	)
	if s.Repo != "" {
		id, err = m.Client.InstallationForRepo(ctx, s.Owner, s.Repo)
		repos = []string{s.Repo}
	} else {
		id, err = m.Client.InstallationForOwner(ctx, s.Owner)
	}
	if err != nil {
		return Token{}, err
	}
	t, err := m.Client.CreateToken(ctx, id, repos, m.Perms)
	if err != nil {
		return Token{}, err
	}
	if err := m.Cache.Put(key, Entry{Token: t.Value, Expires: t.ExpiresAt, MintedAt: m.now()}); err != nil {
		return t, nil // caching is an optimisation; the token is still valid
	}
	return t, nil
}

// Forget removes a scope's cached token (used when git reports it was rejected).
func (m *Manager) Forget(s Scope) error { return m.Cache.Delete(s.Key(m.AppID)) }

// DefaultOwner returns the owner to use when git gives no repository path:
// the only installation's account, otherwise an error.
func (m *Manager) DefaultOwner(ctx context.Context) (string, error) {
	ins, err := m.Client.ListInstallations(ctx)
	if err != nil {
		return "", err
	}
	if len(ins) == 1 {
		return ins[0].Account.Login, nil
	}
	if len(ins) == 0 {
		return "", errors.New("the App has no installations")
	}
	return "", errors.New("the App has several installations; set default_owner in the config or run: git config --global credential.useHttpPath true")
}

// RefreshLoop calls fn immediately and then every interval until ctx ends.
// Errors are passed to onErr; the loop keeps going.
func RefreshLoop(ctx context.Context, interval time.Duration, fn func(context.Context) error, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := fn(ctx); err != nil && onErr != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Mask hides all but a short prefix of a secret for display.
func Mask(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "…" + strings.Repeat("*", 8)
}
