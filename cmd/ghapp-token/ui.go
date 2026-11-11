package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/itsnavin/github-app-token-helper/internal/ghapp"
)

//go:embed ui.html
var uiHTML []byte

type uiServer struct {
	cfgPath string
	key     string
	port    int
}

// newUIHandler builds the HTTP handler. API routes require the per-run key and a
// loopback Host header (blocks DNS-rebinding and other websites calling the API).
func newUIHandler(cfgPath, key string, port int) http.Handler {
	s := &uiServer{cfgPath: cfgPath, key: key, port: port}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || !s.hostOK(r) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(uiHTML)
	})
	mux.HandleFunc("/api/status", s.api("GET", s.status))
	mux.HandleFunc("/api/config", s.api("POST", s.saveConfig))
	mux.HandleFunc("/api/git", s.api("POST", s.gitToggle))
	mux.HandleFunc("/api/clone", s.api("POST", s.clone))
	mux.HandleFunc("/api/token", s.api("POST", s.token))
	mux.HandleFunc("/api/refresh", s.api("POST", s.refresh))
	mux.HandleFunc("/api/browse", s.api("POST", s.browse))
	mux.HandleFunc("/api/bootstrap", s.api("POST", s.bootstrap))
	return mux
}

func (s *uiServer) hostOK(r *http.Request) bool {
	h := strings.ToLower(r.Host)
	return h == fmt.Sprintf("127.0.0.1:%d", s.port) || h == fmt.Sprintf("localhost:%d", s.port)
}

func (s *uiServer) api(method string, fn func(context.Context, *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fail := func(code int, msg string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if r.Method != method {
			fail(405, "method not allowed")
			return
		}
		if !s.hostOK(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-UI-Key")), []byte(s.key)) != 1 {
			fail(403, "forbidden")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		res, err := fn(ctx, r)
		if err != nil {
			fail(400, err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	}
}

// browse opens a native file picker on this machine and returns the chosen path.
// An empty path means the user cancelled or no picker is available.
func (s *uiServer) browse(ctx context.Context, _ *http.Request) (any, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		ps := `Add-Type -AssemblyName System.Windows.Forms; ` +
			`$d = New-Object System.Windows.Forms.OpenFileDialog; ` +
			`$d.Title = 'Select GitHub App private key (.pem)'; ` +
			`$d.Filter = 'PEM key (*.pem)|*.pem|All files (*.*)|*.*'; ` +
			`$d.InitialDirectory = [Environment]::GetFolderPath('UserProfile'); ` +
			`$f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; ` +
			`if ($d.ShowDialog($f) -eq 'OK') { [Console]::Out.Write($d.FileName) }`
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-STA", "-Command", ps)
	case "darwin":
		cmd = exec.CommandContext(ctx, "osascript", "-e", `POSIX path of (choose file with prompt "Select GitHub App private key (.pem)")`)
	default:
		cmd = exec.CommandContext(ctx, "zenity", "--file-selection", "--title=Select GitHub App private key (.pem)")
	}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return map[string]string{"path": ""}, nil
		}
		return nil, errors.New("no file picker available; type the path instead")
	}
	return map[string]string{"path": strings.TrimSpace(string(out))}, nil
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("invalid request")
	}
	return nil
}

type installInfo struct {
	Account string `json:"account"`
	Repos   string `json:"repos"`
}
type cachedInfo struct {
	Scope     string `json:"scope"`
	Token     string `json:"token"`
	Age       string `json:"age"`
	ExpiresIn string `json:"expires_in"`
}

func gitHelperEnabled(host string) bool {
	out, err := exec.Command("git", "config", "--global", "--get-all", "credential.https://"+host+".helper").Output()
	return err == nil && strings.Contains(string(out), "ghapp-token")
}

func (s *uiServer) status(ctx context.Context, _ *http.Request) (any, error) {
	cfg, err := ghapp.LoadConfig(s.cfgPath)
	if err != nil {
		return nil, err
	}
	perm := "read"
	if cfg.Permissions["contents"] == "write" {
		perm = "write"
	}
	res := map[string]any{
		"host": cfg.Host, "app_id": cfg.AppID, "key_path": cfg.KeyPath, "default_owner": cfg.DefaultOwner,
		"permission": perm, "installation_wide": cfg.InstallationWide, "interval": cfg.Interval().String(),
		"git_enabled": gitHelperEnabled(cfg.Host), "installations": []installInfo{}, "cached": []cachedInfo{},
	}
	if cfg.AppID == "" || cfg.KeyPath == "" {
		return res, nil
	}
	m, err := cfg.NewManager(nil)
	if err != nil {
		res["error"] = err.Error()
		return res, nil
	}
	if name, err := m.Client.AppName(ctx); err != nil {
		res["error"] = err.Error()
	} else {
		res["app_name"] = name
	}
	if ins, err := m.Client.ListInstallations(ctx); err == nil {
		list := []installInfo{}
		for _, i := range ins {
			list = append(list, installInfo{i.Account.Login, i.RepositorySelection})
		}
		res["installations"] = list
	}
	all := m.Cache.All()
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cached := []cachedInfo{}
	for _, k := range keys {
		e := all[k]
		cached = append(cached, cachedInfo{k, ghapp.Mask(e.Token), time.Since(e.MintedAt).Round(time.Second).String(), ghapp.ExpiresIn(e.Expires, time.Now())})
	}
	res["cached"] = cached
	return res, nil
}

func (s *uiServer) saveConfig(ctx context.Context, r *http.Request) (any, error) {
	var in struct {
		Host             string `json:"host"`
		AppID            string `json:"app_id"`
		KeyPath          string `json:"key_path"`
		DefaultOwner     string `json:"default_owner"`
		Write            bool   `json:"write"`
		InstallationWide bool   `json:"installation_wide"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	cfg, err := ghapp.LoadConfig(s.cfgPath)
	if err != nil {
		return nil, err
	}
	if in.Host == "" {
		in.Host = "github.com"
	}
	if strings.ContainsAny(in.Host, "/\\ @") {
		return nil, errors.New("host must be a bare hostname such as github.com")
	}
	cfg.Host, cfg.AppID, cfg.DefaultOwner, cfg.InstallationWide = in.Host, strings.TrimSpace(in.AppID), in.DefaultOwner, in.InstallationWide
	if abs, err := filepath.Abs(strings.Trim(in.KeyPath, `"`)); err == nil && in.KeyPath != "" {
		cfg.KeyPath = abs
	}
	cfg.Permissions = map[string]string{"contents": "read"}
	if in.Write {
		cfg.Permissions["contents"] = "write"
	}
	m, err := cfg.NewManager(&ghapp.MemCache{})
	if err != nil {
		return nil, err
	}
	name, err := m.Client.AppName(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not authenticate as the App: %w", err)
	}
	if err := cfg.Save(s.cfgPath); err != nil {
		return nil, err
	}
	return map[string]string{"app_name": name}, nil
}

func (s *uiServer) bootstrap(ctx context.Context, r *http.Request) (any, error) {
	var in struct {
		Host         string `json:"host"`
		AppID        string `json:"app_id"`
		KeyPath      string `json:"key_path"`
		KeyPEM       string `json:"key_pem"`
		DefaultOwner string `json:"default_owner"`
		Write        bool   `json:"write"`
		Repo         string `json:"repo"`
		Dir          string `json:"dir"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Repo != "" && in.Dir == "" {
		return nil, errors.New("enter a destination folder to clone into")
	}
	o := bootstrapOpts{Host: in.Host, AppID: in.AppID, KeyPath: in.KeyPath, KeyPEM: []byte(strings.TrimSpace(in.KeyPEM)),
		DefaultOwner: in.DefaultOwner, Write: in.Write, InstallGit: true, Repo: in.Repo, Dir: in.Dir}
	out, err := bootstrapForUI(ctx, s.cfgPath, o)
	if err != nil {
		return nil, fmt.Errorf("%v\n%s", err, out)
	}
	return map[string]string{"output": out}, nil
}

func (s *uiServer) gitToggle(_ context.Context, r *http.Request) (any, error) {
	var in struct {
		Enable bool `json:"enable"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := cmdInstallGit(s.cfgPath, &buf, !in.Enable); err != nil {
		return nil, err
	}
	return map[string]string{"message": strings.TrimSpace(buf.String())}, nil
}

func (s *uiServer) clone(ctx context.Context, r *http.Request) (any, error) {
	var in struct {
		Repo string `json:"repo"`
		Dir  string `json:"dir"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.Repo == "" || in.Dir == "" {
		return nil, errors.New("repository and destination folder are required")
	}
	var out bytes.Buffer
	if err := cmdClone(ctx, s.cfgPath, []string{in.Repo, in.Dir}, &out, &out); err != nil {
		return nil, fmt.Errorf("%v\n%s", err, out.String())
	}
	return map[string]string{"output": out.String()}, nil
}

func (s *uiServer) token(ctx context.Context, r *http.Request) (any, error) {
	var in struct {
		Scope string `json:"scope"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	sc, err := parseScope(in.Scope)
	if err != nil {
		return nil, err
	}
	_, m, err := loadManager(s.cfgPath)
	if err != nil {
		return nil, err
	}
	t, err := m.Token(ctx, sc, false)
	if err != nil {
		return nil, err
	}
	return map[string]string{"token": t.Value}, nil
}

func (s *uiServer) refresh(ctx context.Context, _ *http.Request) (any, error) {
	_, m, err := loadManager(s.cfgPath)
	if err != nil {
		return nil, err
	}
	ins, err := m.Client.ListInstallations(ctx)
	if err != nil {
		return nil, err
	}
	var errs []error
	n := 0
	for _, i := range ins {
		if _, err := m.Token(ctx, ghapp.Scope{Owner: i.Account.Login}, true); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", i.Account.Login, err))
			continue
		}
		n++
	}
	if n == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return map[string]int{"count": n}, nil
}

func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		c = exec.Command("open", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = c.Start()
}

func cmdUI(ctx context.Context, cfgPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	port := fs.Int("port", 0, "port to listen on at 127.0.0.1 (default: random free port)")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	kb := make([]byte, 24)
	if _, err := rand.Read(kb); err != nil {
		return err
	}
	key := hex.EncodeToString(kb)
	p := ln.Addr().(*net.TCPAddr).Port
	// Git must never block waiting for a terminal prompt from the UI.
	_ = os.Setenv("GIT_TERMINAL_PROMPT", "0")
	srv := &http.Server{Handler: newUIHandler(cfgPath, key, p), ReadHeaderTimeout: 10 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/?k=%s", p, key)
	fmt.Fprintf(stdout, "GitHub App Token Helper UI: %s\nPress Ctrl+C to stop.\n", url)
	if !*noOpen {
		openBrowser(url)
	}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
