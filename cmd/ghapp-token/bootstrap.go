package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/itsnavin/github-app-token-helper/internal/ghapp"
)

// bootstrapOpts describes a complete first-time setup of a machine.
type bootstrapOpts struct {
	Host         string
	AppID        string
	KeyPath      string // existing key file
	KeyPEM       []byte // key contents; stored in the config dir with owner-only permissions
	CopyKey      bool   // copy KeyPath into the config dir with owner-only permissions
	DefaultOwner string
	Write        bool
	InstallGit   bool
	Repo, Dir    string // optional clone
}

const importedKeyName = "app-private-key.pem"

// storeKey saves PEM data in the config dir (0700 dir, 0600 file) and returns its path.
func storeKey(pemData []byte) (string, error) {
	if _, err := ghapp.ParsePrivateKey(pemData); err != nil {
		return "", fmt.Errorf("that is not a valid RSA private key: %w", err)
	}
	dir, err := ghapp.ConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, importedKeyName)
	if err := writeFileAtomic(p, pemData); err != nil {
		return "", err
	}
	return p, nil
}

// bootstrap configures everything needed on a fresh machine: stores/locates the
// key, authenticates as the App, saves the config, registers the git credential
// helper and optionally clones a repository. Progress goes to stdout.
func bootstrap(ctx context.Context, cfgPath string, o bootstrapOpts, stdout, stderr io.Writer) error {
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if o.Host != "" {
		if strings.ContainsAny(o.Host, "/\\ @") {
			return errors.New("host must be a bare hostname such as github.com")
		}
		cfg.Host = o.Host
	}
	if o.AppID != "" {
		cfg.AppID = strings.TrimSpace(o.AppID)
	}
	if o.DefaultOwner != "" {
		cfg.DefaultOwner = o.DefaultOwner
	}
	if o.Repo != "" && cfg.DefaultOwner == "" {
		if s, err := parseScope(o.Repo); err == nil {
			cfg.DefaultOwner = s.Owner
		}
	}

	switch {
	case len(o.KeyPEM) > 0:
		p, err := storeKey(o.KeyPEM)
		if err != nil {
			return err
		}
		cfg.KeyPath = p
		fmt.Fprintln(stdout, "[1/4] Private key stored (owner-only):", p)
	case o.KeyPath != "":
		p, err := filepath.Abs(strings.Trim(o.KeyPath, `"`))
		if err != nil {
			return err
		}
		if o.CopyKey {
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("cannot read private key file: %w", err)
			}
			if p, err = storeKey(data); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "[1/4] Private key copied (owner-only):", p)
		} else {
			cfg.KeyPath = p
			fmt.Fprintln(stdout, "[1/4] Using private key:", p)
		}
		cfg.KeyPath = p
	default:
		fmt.Fprintln(stdout, "[1/4] Using saved private key:", cfg.KeyPath)
	}
	cfg.Permissions = map[string]string{"contents": "read"}
	if o.Write {
		cfg.Permissions["contents"] = "write"
	}

	m, err := cfg.NewManager(&ghapp.MemCache{})
	if err != nil {
		return err
	}
	name, err := m.Client.AppName(ctx)
	if err != nil {
		return fmt.Errorf("could not authenticate as the App (check App ID and key): %w", err)
	}
	fmt.Fprintf(stdout, "[2/4] Authenticated as GitHub App %q\n", name)
	if ins, err := m.Client.ListInstallations(ctx); err == nil {
		if len(ins) == 0 {
			fmt.Fprintln(stdout, "      WARNING: the App is not installed anywhere yet; install it on your repos.")
		}
		for _, i := range ins {
			fmt.Fprintf(stdout, "      installed on %s (repos: %s)\n", i.Account.Login, i.RepositorySelection)
		}
	}
	if err := cfg.Save(cfgPath); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "      Config saved:", cfgPath)

	if o.InstallGit {
		if err := cmdInstallGit(cfgPath, stdout, false); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "[3/4] git credential helper registered")
	} else {
		fmt.Fprintln(stdout, "[3/4] Skipped git helper registration")
	}

	if o.Repo == "" {
		fmt.Fprintln(stdout, "[4/4] No repository given; done. Try: git clone https://"+cfg.Host+"/OWNER/REPO.git")
		return nil
	}
	args := []string{o.Repo}
	if o.Dir != "" {
		args = append(args, o.Dir)
	}
	fmt.Fprintln(stdout, "[4/4] Cloning", o.Repo)
	return cmdClone(ctx, cfgPath, args, stdout, stderr)
}

func cmdBootstrap(ctx context.Context, cfgPath string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	o := bootstrapOpts{}
	fs.StringVar(&o.Host, "host", "", "GitHub host (default github.com)")
	fs.StringVar(&o.AppID, "app-id", "", "GitHub App ID")
	fs.StringVar(&o.KeyPath, "key", "", "path to the App private key .pem")
	fs.BoolVar(&o.CopyKey, "copy-key", false, "copy --key into the config dir with owner-only permissions")
	keyStdin := fs.Bool("key-stdin", false, "read the private key PEM from standard input and store it securely")
	fs.StringVar(&o.DefaultOwner, "owner", "", "default owner/account")
	fs.BoolVar(&o.Write, "write", false, "request contents:write instead of read-only")
	noGit := fs.Bool("no-git", false, "do not register the git credential helper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 2 {
		return errors.New("usage: ghapp-token bootstrap [flags] [owner/repo [dir]]")
	}
	if fs.NArg() >= 1 {
		o.Repo = fs.Arg(0)
	}
	if fs.NArg() == 2 {
		o.Dir = fs.Arg(1)
	}
	o.InstallGit = !*noGit

	if *keyStdin {
		data, err := io.ReadAll(io.LimitReader(stdin, 1<<16))
		if err != nil {
			return err
		}
		o.KeyPEM = data
	}
	// Ask for anything still missing so a beginner can just run `ghapp-token bootstrap`.
	cfg, err := ghapp.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	r := bufio.NewReader(stdin)
	if o.AppID == "" && cfg.AppID == "" {
		o.AppID = prompt(r, stdout, "App ID", "")
	}
	if len(o.KeyPEM) == 0 && o.KeyPath == "" && cfg.KeyPath == "" {
		o.KeyPath = prompt(r, stdout, "Path to the private key .pem file", "")
		o.CopyKey = true
	}
	if o.Repo == "" {
		o.Repo = prompt(r, stdout, "Repository to clone (owner/repo, empty to skip)", "")
		if o.Repo != "" && o.Dir == "" {
			o.Dir = prompt(r, stdout, "Destination folder (empty = current folder)", "")
		}
	}
	return bootstrap(ctx, cfgPath, o, stdout, stderr)
}

// bootstrapForUI runs bootstrap and returns its progress log.
func bootstrapForUI(ctx context.Context, cfgPath string, o bootstrapOpts) (string, error) {
	var out bytes.Buffer
	err := bootstrap(ctx, cfgPath, o, &out, &out)
	return out.String(), err
}
