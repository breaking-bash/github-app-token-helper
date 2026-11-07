package ghapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config is stored as JSON. It contains only the *path* to the private key,
// never the key itself.
type Config struct {
	AppID        string            `json:"app_id"`
	KeyPath      string            `json:"private_key_path"`
	Host         string            `json:"host"`                    // github.com or a GHES hostname
	APIURL       string            `json:"api_url,omitempty"`       // override; derived from Host when empty
	DefaultOwner string            `json:"default_owner,omitempty"` // used when git sends no repo path
	Permissions  map[string]string `json:"permissions,omitempty"`   // default {"contents":"read"}
	RefreshEvery string            `json:"refresh_interval,omitempty"`
	// InstallationWide mints one token per owner instead of one per repository.
	InstallationWide bool `json:"installation_wide,omitempty"`
}

// ConfigDir returns the per-user directory used for config and cache.
func ConfigDir() (string, error) {
	if d := os.Getenv("GHAPP_TOKEN_HOME"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "github-app-token-helper"), nil
}

// ConfigPath is the config file location.
func ConfigPath() (string, error) {
	d, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// LoadConfig reads the config file (if any) and applies environment overrides:
// GHAPP_APP_ID, GHAPP_PRIVATE_KEY_PATH, GHAPP_HOST, GHAPP_API_URL, GHAPP_DEFAULT_OWNER.
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config %s is not valid JSON: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if v := os.Getenv("GHAPP_APP_ID"); v != "" {
		c.AppID = v
	}
	if v := os.Getenv("GHAPP_PRIVATE_KEY_PATH"); v != "" {
		c.KeyPath = v
	}
	if v := os.Getenv("GHAPP_HOST"); v != "" {
		c.Host = v
	}
	if v := os.Getenv("GHAPP_API_URL"); v != "" {
		c.APIURL = v
	}
	if v := os.Getenv("GHAPP_DEFAULT_OWNER"); v != "" {
		c.DefaultOwner = v
	}
	if c.Host == "" {
		c.Host = "github.com"
	}
	if len(c.Permissions) == 0 {
		c.Permissions = map[string]string{"contents": "read"}
	}
	return c, nil
}

// Save writes the config with owner-only permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if c.AppID == "" {
		return errors.New("no App ID configured (run `ghapp-token setup` or set GHAPP_APP_ID)")
	}
	if c.KeyPath == "" {
		return errors.New("no private key path configured (run `ghapp-token setup` or set GHAPP_PRIVATE_KEY_PATH)")
	}
	return nil
}

// API returns the REST API base URL.
func (c *Config) API() string {
	if c.APIURL != "" {
		return strings.TrimRight(c.APIURL, "/")
	}
	if c.Host == "" || strings.EqualFold(c.Host, "github.com") {
		return "https://api.github.com"
	}
	return "https://" + c.Host + "/api/v3"
}

// Interval returns the refresh interval (default 10 minutes).
func (c *Config) Interval() time.Duration {
	if d, err := time.ParseDuration(c.RefreshEvery); err == nil && d > 0 {
		return d
	}
	return DefaultMaxAge
}

// NewManager builds a Manager from the config. If cache is nil a protected
// file cache in the config dir is used.
func (c *Config) NewManager(cache Cache) (*Manager, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	pemBytes, err := ReadKeyFile(c.KeyPath)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		dir, err := ConfigDir()
		if err != nil {
			return nil, err
		}
		cache = &FileCache{Path: filepath.Join(dir, "tokens.json")}
	}
	return &Manager{
		Client: &Client{BaseURL: c.API(), AppID: c.AppID, Key: key},
		Cache:  cache,
		AppID:  c.AppID,
		Perms:  c.Permissions,
		MaxAge: c.Interval(),
	}, nil
}

// ReadKeyFile reads the key file. On Unix it refuses keys readable by
// group/others, like ssh does.
func ReadKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key file: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s is accessible by other users (mode %o); run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	return os.ReadFile(path)
}
