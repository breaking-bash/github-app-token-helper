// Command ghapp-token mints short-lived GitHub App installation tokens and
// acts as a git credential helper.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/itsnavin/github-app-token-helper/internal/ghapp"
)

var version = "dev"

const usage = `ghapp-token ` + "%s" + ` - GitHub App tokens for git, refreshed every 10 minutes

Usage:
  ghapp-token bootstrap [flags] [owner/repo [dir]]   one step: save key+config, enable git, clone
  ghapp-token setup [--install-git]     interactive setup wizard
  ghapp-token token <owner>[/<repo>]    print a fresh token (repo = scoped to that repo)
  ghapp-token clone <owner/repo> [dir]  git clone using a token (never put in the URL)
  ghapp-token credential <get|store|erase>   git credential helper (used by git)
  ghapp-token install-git               register as git credential helper for the host
  ghapp-token uninstall-git             remove that registration
  ghapp-token daemon [--owner o] [--out file] [--interval 10m]   keep tokens refreshed
  ghapp-token ui [--port n] [--no-open]  graphical setup in your browser (localhost only)
  ghapp-token status                    show config, installations, cached tokens (masked)
  ghapp-token version

Config: %s   (env overrides: GHAPP_APP_ID, GHAPP_PRIVATE_KEY_PATH, GHAPP_HOST, GHAPP_API_URL, GHAPP_DEFAULT_OWNER)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfgPath, err := ghapp.ConfigPath()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(stderr, usage, version, cfgPath)
		return 2
	}
	cmd, rest := args[0], args[1:]
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cerr error
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, version)
	case "setup":
		cerr = cmdSetup(ctx, cfgPath, rest, stdin, stdout)
	case "bootstrap":
		cerr = cmdBootstrap(ctx, cfgPath, rest, stdin, stdout, stderr)
	case "token":
		cerr = cmdToken(ctx, cfgPath, rest, stdout)
	case "clone":
		cerr = cmdClone(ctx, cfgPath, rest, stdout, stderr)
	case "credential":
		cerr = cmdCredential(ctx, cfgPath, rest, stdin, stdout)
	case "install-git":
		cerr = cmdInstallGit(cfgPath, stdout, false)
	case "uninstall-git":
		cerr = cmdInstallGit(cfgPath, stdout, true)
	case "daemon":
		cerr = cmdDaemon(ctx, cfgPath, rest, stdout, stderr)
	case "ui":
		cerr = cmdUI(ctx, cfgPath, rest, stdout)
	case "status":
		cerr = cmdStatus(ctx, cfgPath, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", cmd)
		fmt.Fprintf(stderr, usage, version, cfgPath)
		return 2
	}
	if cerr != nil {
		fmt.Fprintln(stderr, "error:", cerr)
		return 1
	}
	return 0
}

func loadManager(cfgPath string) (*ghapp.Config, *ghapp.Manager, error) {
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	var cache ghapp.Cache
	if os.Getenv("GHAPP_NO_CACHE") != "" {
		cache = &ghapp.MemCache{}
	}
	m, err := cfg.NewManager(cache)
	return cfg, m, err
}

func parseScope(arg string) (ghapp.Scope, error) {
	owner, repo, _ := strings.Cut(arg, "/")
	repo = strings.TrimSuffix(repo, ".git")
	if owner == "" || strings.Contains(repo, "/") {
		return ghapp.Scope{}, fmt.Errorf("expected <owner> or <owner>/<repo>, got %q", arg)
	}
	return ghapp.Scope{Owner: owner, Repo: repo}, nil
}

func cmdToken(ctx context.Context, cfgPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	force := fs.Bool("new", false, "always mint a new token instead of using the cached one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ghapp-token token [--new] <owner>[/<repo>]")
	}
	s, err := parseScope(fs.Arg(0))
	if err != nil {
		return err
	}
	_, m, err := loadManager(cfgPath)
	if err != nil {
		return err
	}
	t, err := m.Token(ctx, s, *force)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, t.Value)
	return nil
}

func helperCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return `!"` + filepath.ToSlash(exe) + `" credential`, nil
}

func cmdCredential(ctx context.Context, cfgPath string, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: ghapp-token credential <get|store|erase>")
	}
	in := ghapp.ParseCredentialInput(stdin)
	cfg, m, err := loadManager(cfgPath)
	if err != nil {
		return err
	}
	h := &ghapp.CredentialHandler{Manager: m, Host: cfg.Host, DefaultOwner: cfg.DefaultOwner, InstallationWide: cfg.InstallationWide}
	return h.Handle(ctx, args[0], in, stdout)
}

func git(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	c := exec.CommandContext(ctx, "git", args...)
	c.Stdout, c.Stderr, c.Stdin = stdout, stderr, os.Stdin
	return c.Run()
}

func cmdClone(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: ghapp-token clone <owner/repo> [dir]")
	}
	s, err := parseScope(args[0])
	if err != nil || s.Repo == "" {
		return errors.New("usage: ghapp-token clone <owner/repo> [dir]")
	}
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	helper, err := helperCommand()
	if err != nil {
		return err
	}
	gargs := []string{
		"-c", "credential.helper=", "-c", "credential.helper=" + helper,
		"-c", "credential.useHttpPath=true",
		"clone", fmt.Sprintf("https://%s/%s/%s.git", cfg.Host, s.Owner, s.Repo),
	}
	if len(args) == 2 {
		if strings.HasPrefix(args[1], "-") {
			return errors.New("destination folder must not start with '-'")
		}
		gargs = append(gargs, args[1])
	}
	return git(ctx, stdout, stderr, gargs...)
}

func cmdInstallGit(cfgPath string, stdout io.Writer, remove bool) error {
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	prefix := "credential.https://" + cfg.Host + "."
	ctx := context.Background()
	if remove {
		_ = git(ctx, io.Discard, io.Discard, "config", "--global", "--unset-all", prefix+"helper")
		_ = git(ctx, io.Discard, io.Discard, "config", "--global", "--unset", prefix+"useHttpPath")
		fmt.Fprintln(stdout, "Removed git credential helper for", cfg.Host)
		return nil
	}
	helper, err := helperCommand()
	if err != nil {
		return err
	}
	steps := [][]string{
		{"config", "--global", "--replace-all", prefix + "helper", ""},
		{"config", "--global", "--add", prefix + "helper", helper},
		{"config", "--global", prefix + "useHttpPath", "true"},
	}
	for _, a := range steps {
		if err := git(ctx, io.Discard, os.Stderr, a...); err != nil {
			return fmt.Errorf("git %s failed: %w", strings.Join(a[:3], " "), err)
		}
	}
	fmt.Fprintf(stdout, "git now uses ghapp-token for https://%s (try: git clone https://%s/OWNER/REPO.git)\n", cfg.Host, cfg.Host)
	return nil
}

func cmdDaemon(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	var owners multiFlag
	fs.Var(&owners, "owner", "owner (user/org) to refresh a whole-installation token for; repeatable (default: every installation)")
	out := fs.String("out", "", "write the token to this file (0600, atomically replaced); requires exactly one --owner")
	interval := fs.Duration("interval", 0, "refresh interval (default from config, 10m)")
	once := fs.Bool("once", false, "refresh once and exit (for Task Scheduler/cron/systemd timers)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out != "" && len(owners) != 1 {
		return errors.New("--out requires exactly one --owner")
	}
	cfg, m, err := loadManager(cfgPath)
	if err != nil {
		return err
	}
	if *interval == 0 {
		*interval = cfg.Interval()
	}
	m.MaxAge = *interval
	refresh := func(ctx context.Context) error {
		list := []string(owners)
		if len(list) == 0 {
			ins, err := m.Client.ListInstallations(ctx)
			if err != nil {
				return err
			}
			for _, i := range ins {
				list = append(list, i.Account.Login)
			}
		}
		var errs []error
		for _, o := range list {
			t, err := m.Token(ctx, ghapp.Scope{Owner: o}, true)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", o, err))
				continue
			}
			if *out != "" {
				if err := writeFileAtomic(*out, []byte(t.Value+"\n")); err != nil {
					errs = append(errs, err)
					continue
				}
			}
			fmt.Fprintf(stdout, "%s refreshed token for %s (expires %s)\n", time.Now().Format(time.RFC3339), o, t.ExpiresAt.Local().Format(time.RFC3339))
		}
		return errors.Join(errs...)
	}
	if *once {
		return refresh(ctx)
	}
	ghapp.RefreshLoop(ctx, *interval, refresh, func(err error) { fmt.Fprintln(stderr, "refresh failed:", err) })
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tok-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func cmdStatus(ctx context.Context, cfgPath string, stdout io.Writer) error {
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config file : %s\nhost        : %s (API %s)\napp id      : %s\nkey file    : %s\npermissions : %v\nrefresh     : every %s\n",
		cfgPath, cfg.Host, cfg.API(), orNone(cfg.AppID), orNone(cfg.KeyPath), cfg.Permissions, cfg.Interval())
	_, m, err := loadManager(cfgPath)
	if err != nil {
		fmt.Fprintln(stdout, "not ready  :", err)
		return nil
	}
	if name, err := m.Client.AppName(ctx); err != nil {
		fmt.Fprintln(stdout, "app check   : FAILED:", err)
	} else {
		fmt.Fprintln(stdout, "app check   : OK, app name:", name)
	}
	if ins, err := m.Client.ListInstallations(ctx); err == nil {
		fmt.Fprintf(stdout, "installed on: %d account(s)\n", len(ins))
		for _, i := range ins {
			fmt.Fprintf(stdout, "  - %s (repos: %s)\n", i.Account.Login, i.RepositorySelection)
		}
	}
	all := m.Cache.All()
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(stdout, "cached tokens: %d\n", len(keys))
	for _, k := range keys {
		e := all[k]
		fmt.Fprintf(stdout, "  - %s  %s  age %s, expires in %s\n", k, ghapp.Mask(e.Token), time.Since(e.MintedAt).Round(time.Second), ghapp.ExpiresIn(e.Expires, time.Now()))
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func prompt(r *bufio.Reader, w io.Writer, q, def string) string {
	if def != "" {
		fmt.Fprintf(w, "%s [%s]: ", q, def)
	} else {
		fmt.Fprintf(w, "%s: ", q)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func cmdSetup(ctx context.Context, cfgPath string, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	installGit := fs.Bool("install-git", false, "also register as the git credential helper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	r := bufio.NewReader(stdin)
	fmt.Fprintln(stdout, "GitHub App token helper setup. See docs/SETUP.md to create the App first.")
	cfg.Host = prompt(r, stdout, "GitHub host (github.com or your GitHub Enterprise Server host)", cfg.Host)
	cfg.AppID = prompt(r, stdout, "App ID (number on the App settings page)", cfg.AppID)
	cfg.KeyPath = prompt(r, stdout, "Path to the downloaded private key .pem file", cfg.KeyPath)
	cfg.DefaultOwner = prompt(r, stdout, "Default owner (optional; used if git sends no repo path)", cfg.DefaultOwner)
	if abs, err := filepath.Abs(cfg.KeyPath); err == nil {
		cfg.KeyPath = abs
	}
	m, err := cfg.NewManager(&ghapp.MemCache{})
	if err != nil {
		return err
	}
	name, err := m.Client.AppName(ctx)
	if err != nil {
		return fmt.Errorf("could not authenticate as the App: %w", err)
	}
	fmt.Fprintf(stdout, "Authenticated as GitHub App %q.\n", name)
	if ins, err := m.Client.ListInstallations(ctx); err == nil {
		if len(ins) == 0 {
			fmt.Fprintln(stdout, "WARNING: the App is not installed anywhere yet; install it on your account/org/repos.")
		}
		for _, i := range ins {
			fmt.Fprintf(stdout, "  installed on %s (repos: %s)\n", i.Account.Login, i.RepositorySelection)
		}
	}
	if err := cfg.Save(cfgPath); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Saved", cfgPath, "(the private key itself is NOT copied; keep it safe).")
	if *installGit {
		return cmdInstallGit(cfgPath, stdout, false)
	}
	fmt.Fprintln(stdout, "Next: ghapp-token install-git   (then plain `git clone` works)")
	return nil
}
