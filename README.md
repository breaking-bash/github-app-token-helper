# github-app-token-helper

`ghapp-token` is a small cross-platform CLI (Windows, Linux, macOS; no dependencies) that uses a **GitHub App** to mint short-lived installation tokens and hands them to **git**, so `git clone/fetch/pull` works across every repository the App is installed on — **outside GitHub Actions**.

> **About "10 minutes":** GitHub App installation tokens always live **1 hour** and that cannot be shortened. This tool enforces its own policy: a token older than **10 minutes** is never reused; a new one is minted. (Configurable via `refresh_interval`.)

## How it works

```
git ──► ghapp-token credential get ──► signs a 9-minute RS256 JWT with your App key
                                    ──► finds the installation for owner/repo
                                    ──► POST /app/installations/{id}/access_tokens (contents: read, only that repo)
                                    ◄── token (cached ≤10 min in a 0600 file, handed to git over stdin/stdout, never in a URL)
```

## Quick start

1. Create the App, key and installation — [docs/SETUP.md](docs/SETUP.md) (step by step).
2. Download a binary from [Releases](https://github.com/itsnavin/github-app-token-helper/releases) (verify with `checksums.txt`).
3. `ghapp-token setup --install-git`
4. `git clone https://github.com/OWNER/REPO.git` — done.

## Commands

| Command | Purpose |
|---|---|
| `setup [--install-git]` | Wizard: validates App ID + key against GitHub, lists installations, saves config |
| `install-git` / `uninstall-git` | Register/remove the credential helper for your host in `git config --global` |
| `credential get\|store\|erase` | The git credential helper protocol (called by git) |
| `clone <owner/repo> [dir]` | One-off clone using a token without installing the helper globally |
| `token [--new] <owner>[/<repo>]` | Print a token (repo-scoped if `/repo` given) |
| `daemon [--once] [--owner o] [--out file] [--interval 10m]` | Refresh tokens on a timer; optionally write one to a file |
| `status` | Config, App check, installations, cached tokens (masked) |

Config lives in the user config dir (`%AppData%\github-app-token-helper\config.json`, `~/.config/github-app-token-helper/config.json`). Example:

```json
{
  "app_id": "1234567",
  "private_key_path": "C:\\Users\\me\\.ghapp\\app.pem",
  "host": "github.com",
  "default_owner": "",
  "permissions": { "contents": "read" },
  "refresh_interval": "10m",
  "installation_wide": false
}
```

Environment overrides: `GHAPP_APP_ID`, `GHAPP_PRIVATE_KEY_PATH`, `GHAPP_HOST`, `GHAPP_API_URL`, `GHAPP_DEFAULT_OWNER`, `GHAPP_TOKEN_HOME`, `GHAPP_NO_CACHE=1`.

**GitHub Enterprise Server:** set `host` to your GHES hostname (API defaults to `https://HOST/api/v3`, or set `api_url`).

**Least privilege:** by default tokens are scoped to the single repository being accessed and to `contents: read`. To allow pushes set `"permissions": {"contents": "write"}` (the App must have that permission). Set `installation_wide: true` for one token per owner covering all its repos.

## GitHub Actions

Inside Actions use the official [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token); a reusable example is in [.github/workflows/example-app-token-clone.yml](.github/workflows/example-app-token-clone.yml).

## Security

- The **private key is only referenced by path**; it is never copied, logged, or sent anywhere. The tool refuses (Linux/macOS) key files readable by others. **Anyone holding the key can mint tokens for every installation of the App** — guard it like a password, don't sync it to cloud folders, and revoke it in App settings if exposed.
- Tokens are given to git over the credential-helper pipe, never embedded in remote URLs or command lines, and `status` masks them. `ghapp-token token` prints the raw token to stdout by design — don't paste it into logs or shell history.
- The token cache (`tokens.json`) is written `0600` in a `0700` directory on Linux/macOS. On Windows it relies on your user-profile folder ACLs (Go can't set per-file ACLs portably). Set `GHAPP_NO_CACHE=1` to keep tokens in memory only (each git call then mints a new token).
- **Not implemented:** OS keystore storage (Windows Credential Manager/DPAPI, libsecret/Keychain) for the private key. File + permissions only.
- JWTs are RS256, 9-minute lifetime, `iat` backdated 60 s for clock skew. No telemetry; the only network calls go to your configured GitHub API host.

## Limitations / when NOT to use this

- Only works for repositories where the App is **installed**; it cannot access repos you merely have access to as a user, or other orgs unless installed there.
- HTTPS only (no SSH). For a single machine/repo, an **SSH deploy key** or a **fine-grained PAT** may be simpler.
- Token can't be shorter than GitHub's 1 hour; the 10-minute refresh is client-side policy and does not revoke the old token (it just expires on its own).
- It does not run as a Windows service itself; use Task Scheduler (see SETUP.md). `daemon --once` + scheduler is optional because the helper refreshes on demand.
- Git Credential Manager is bypassed for the configured host after `install-git`; use `uninstall-git` to revert.

## Testing status (honest)

Automated tests (`go test ./...`, also run in CI on Linux/Windows/macOS) use a **mock GitHub API** that verifies JWT signatures/claims: signing, key parsing, token reuse < 10 min and refresh after, near-expiry replacement, repo/installation scoping, error handling & retries, secret non-leakage, credential-helper protocol, file cache (permissions, corruption), refresh loop, config, and an end-to-end CLI test. The credential helper was also exercised with real `git credential fill` against a local mock API. **It has not been tested against live GitHub** (no real App was available): the request shapes follow GitHub's documented REST API, but expect to verify with your own App.

## Development

```
go vet ./... && go test ./...
go build -o ghapp-token ./cmd/ghapp-token
```

Releases are built by CI when a `v*` tag is pushed (6 binaries + `checksums.txt`).

## License

MIT — see [LICENSE](LICENSE).
