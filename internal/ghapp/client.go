package ghapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token is a GitHub App installation access token.
type Token struct {
	Value     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// APIError is an error response from the GitHub API. It never contains tokens.
type APIError struct {
	Status  int
	Message string
	Path    string
}

func (e *APIError) Error() string {
	hint := ""
	switch e.Status {
	case 401:
		hint = " (check the App ID and that the private key belongs to this App; check your system clock)"
	case 403:
		hint = " (rate limited or the App lacks permission)"
	case 404:
		hint = " (the App is not installed there, or the repository/owner does not exist)"
	case 422:
		hint = " (the requested repositories/permissions are not granted to the App installation)"
	}
	return fmt.Sprintf("GitHub API %s returned %d: %s%s", e.Path, e.Status, e.Message, hint)
}

// Installation describes where the App is installed.
type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
	RepositorySelection string `json:"repository_selection"`
}

// Client talks to the GitHub API as a GitHub App.
type Client struct {
	BaseURL string // e.g. https://api.github.com
	AppID   string
	Key     *rsa.PrivateKey
	HTTP    *http.Client
	Now     func() time.Time
	// RetryDelay is the base back-off between retries (default 500ms).
	RetryDelay time.Duration
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type transientErr struct{ error }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	delay := c.RetryDelay
	if delay == 0 {
		delay = 500 * time.Millisecond
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * delay):
			}
		}
		err := c.doOnce(ctx, method, path, body, out)
		if ae, ok := err.(*APIError); ok && ae.Status >= 500 {
			lastErr = err
			continue
		}
		if te, ok := err.(transientErr); ok {
			lastErr = te.error
			continue
		}
		return err
	}
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, method, path string, body any, out any) error {
	jwt, err := SignJWT(c.Key, c.AppID, c.now())
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "github-app-token-helper")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return transientErr{fmt.Errorf("request to %s failed: %w", path, unwrapURLErr(err))}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message, Path: path}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response from %s: %w", path, err)
		}
	}
	return nil
}

func unwrapURLErr(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

// AppName returns the App's name (also verifies the App ID + private key).
func (c *Client) AppName(ctx context.Context) (string, error) {
	var a struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := c.do(ctx, "GET", "/app", nil, &a); err != nil {
		return "", err
	}
	if a.Name != "" {
		return a.Name, nil
	}
	return a.Slug, nil
}

// ListInstallations lists all installations of the App.
func (c *Client) ListInstallations(ctx context.Context) ([]Installation, error) {
	var all []Installation
	for page := 1; page <= 20; page++ {
		var batch []Installation
		if err := c.do(ctx, "GET", fmt.Sprintf("/app/installations?per_page=100&page=%d", page), nil, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

// InstallationForRepo finds the installation covering owner/repo.
func (c *Client) InstallationForRepo(ctx context.Context, owner, repo string) (int64, error) {
	var in Installation
	err := c.do(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/installation", nil, &in)
	return in.ID, err
}

// InstallationForOwner finds the installation on a user or organization.
func (c *Client) InstallationForOwner(ctx context.Context, owner string) (int64, error) {
	var in Installation
	err := c.do(ctx, "GET", "/orgs/"+url.PathEscape(owner)+"/installation", nil, &in)
	if ae, ok := err.(*APIError); ok && ae.Status == 404 {
		err = c.do(ctx, "GET", "/users/"+url.PathEscape(owner)+"/installation", nil, &in)
	}
	return in.ID, err
}

// CreateToken mints an installation token. repos (names, without owner) and
// perms narrow the token; empty means the installation's full grant.
func (c *Client) CreateToken(ctx context.Context, installationID int64, repos []string, perms map[string]string) (Token, error) {
	body := map[string]any{}
	if len(repos) > 0 {
		body["repositories"] = repos
	}
	if len(perms) > 0 {
		body["permissions"] = perms
	}
	var t Token
	if err := c.do(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installationID), body, &t); err != nil {
		return Token{}, err
	}
	if t.Value == "" {
		return Token{}, fmt.Errorf("GitHub returned an empty token")
	}
	return t, nil
}
