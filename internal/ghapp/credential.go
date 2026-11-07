package ghapp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// ParseCredentialInput reads git's key=value credential protocol until a blank line/EOF.
func ParseCredentialInput(r io.Reader) map[string]string {
	in := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			in[k] = v
		}
	}
	return in
}

// ScopeFromPath extracts owner/repo from a credential "path" ("owner/repo.git").
func ScopeFromPath(path string) (Scope, bool) {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Scope{}, false
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return Scope{}, false
	}
	return Scope{Owner: parts[0], Repo: repo}, true
}

// CredentialHandler implements `git credential` helper operations.
type CredentialHandler struct {
	Manager      *Manager
	Host         string // e.g. github.com
	DefaultOwner string // optional
	// InstallationWide mints whole-installation tokens instead of per-repo ones.
	InstallationWide bool
}

// Handle processes one helper invocation (op is get, store, or erase).
// For unknown hosts/protocols it prints nothing so other helpers can answer.
func (h *CredentialHandler) Handle(ctx context.Context, op string, in map[string]string, out io.Writer) error {
	if in["protocol"] != "https" || !strings.EqualFold(in["host"], h.Host) {
		return nil
	}
	scope, hasPath := ScopeFromPath(in["path"])
	if !hasPath {
		owner := h.DefaultOwner
		if owner == "" && op == "get" {
			var err error
			if owner, err = h.Manager.DefaultOwner(ctx); err != nil {
				return err
			}
		}
		scope = Scope{Owner: owner}
	}
	if h.InstallationWide {
		scope.Repo = ""
	}
	switch op {
	case "get":
		t, err := h.Manager.Token(ctx, scope, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "username=x-access-token\npassword=%s\n", t.Value)
		if !t.ExpiresAt.IsZero() {
			fmt.Fprintf(out, "password_expiry_utc=%d\n", t.ExpiresAt.Add(-DefaultMinValidity).Unix())
		}
	case "erase":
		// Git calls erase when the credential was rejected; drop it so the next get re-mints.
		if scope.Owner != "" {
			return h.Manager.Forget(scope)
		}
	case "store":
		// Tokens are managed by us; nothing to store.
	default:
		return fmt.Errorf("unknown credential operation %q", op)
	}
	return nil
}

// ExpiresIn is a display helper.
func ExpiresIn(t time.Time, now time.Time) string {
	d := t.Sub(now).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	return d.String()
}
