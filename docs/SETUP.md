# Setup guide (beginner friendly)

You do this **once**. Takes ~10 minutes.

## 1. Create the GitHub App

1. Open <https://github.com/settings/apps> (personal account) — or for an organization:
   `https://github.com/organizations/<ORG>/settings/apps` — then click **New GitHub App**.
2. **GitHub App name**: anything unique, e.g. `my-clone-helper`.
3. **Homepage URL**: any URL (e.g. your repo URL).
4. **Webhook**: **uncheck "Active"** (not needed).
5. **Permissions → Repository permissions**:
   - **Contents: Read-only** (needed to clone/fetch/pull)
   - **Metadata: Read-only** (selected automatically)
   - Only add *Read and write* on Contents if you also want to `git push`, and then change `permissions` in the config (see README).
6. **Where can this GitHub App be installed?**: *Only on this account* (safest).
7. Click **Create GitHub App**.

## 2. Find the App ID

After creating, you land on the App's settings page. The number next to **App ID** (e.g. `1234567`) is your App ID. (Not the Client ID, which looks like `Iv1.abc...`.)

## 3. Generate and download the private key

1. On the same page scroll to **Private keys → Generate a private key**.
2. A `.pem` file downloads. Move it somewhere only you can read:
   - **Windows**: `C:\Users\<you>\.ghapp\app.pem`. It inherits your user-profile permissions; do not put it in a shared or synced (OneDrive/Dropbox) folder.
   - **Linux/macOS**: `~/.ghapp/app.pem` then `chmod 600 ~/.ghapp/app.pem` (the tool refuses keys readable by others).
3. **Never commit this file, paste it in chat, or upload it anywhere.**
   Anyone with it can mint tokens for *every* repository the App is installed on.

## 4. Install the App on your repositories

1. In the App settings click **Install App** (left sidebar) → choose your account/org → **Install**.
2. Choose **All repositories** (so it works "in all repos") or **Only select repositories**.
3. The App can only access repositories where it is installed. If you create new repos later and chose "Only select", add them in the installation settings.

## 5. Install the tool

Download the binary for your OS from the [Releases page](https://github.com/itsnavin/github-app-token-helper/releases), verify it against `checksums.txt`, and put it on your `PATH`:

```powershell
# Windows PowerShell
(Get-FileHash .\ghapp-token_windows_amd64.exe -Algorithm SHA256).Hash
# compare with the line in checksums.txt
Rename-Item ghapp-token_windows_amd64.exe ghapp-token.exe
```

```bash
# Linux / macOS
sha256sum -c --ignore-missing checksums.txt
chmod +x ghapp-token_linux_amd64 && sudo mv ghapp-token_linux_amd64 /usr/local/bin/ghapp-token
```

## 6. Run the wizard

```
ghapp-token setup --install-git
```

Answer the prompts (host `github.com`, App ID, path to the `.pem`). The wizard authenticates to GitHub as the App, lists where it is installed, saves the config and registers the git credential helper.

Now this just works, for any repo the App is installed on, with a fresh token each time it is needed:

```
git clone https://github.com/OWNER/REPO.git
```

## 7. (Optional) Keep tokens refreshed in the background every 10 minutes

The credential helper already replaces any token older than 10 minutes the moment git asks for one, so a daemon is only needed to **pre-warm** the cache or to write a token to a **file** for other tools.

**Windows (Task Scheduler)** — run every 10 minutes:

```powershell
$a = New-ScheduledTaskAction -Execute "ghapp-token.exe" -Argument "daemon --once"
$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName "ghapp-token-refresh" -Action $a -Trigger $t
```

**Linux (systemd user service)** `~/.config/systemd/user/ghapp-token.service`:

```ini
[Unit]
Description=GitHub App token refresher
[Service]
ExecStart=%h/.local/bin/ghapp-token daemon
Restart=on-failure
[Install]
WantedBy=default.target
```

Then `systemctl --user enable --now ghapp-token`.

To write the token for one owner to a file other tools read: `ghapp-token daemon --owner my-org --out ~/.ghapp/token`.

## Troubleshooting

| Message | Meaning |
|---|---|
| `returned 401` | Wrong App ID, wrong key file, or your clock is off by more than a few minutes. |
| `returned 404 ... not installed` | The App isn't installed on that repo/owner, or the repo doesn't exist. |
| `returned 422` | Requested permission isn't granted to the App; edit the App's permissions and accept the change on the installation. |
| `accessible by other users` | `chmod 600` your key file (Linux/macOS). |
| Git still asks for a password | Another helper answered first; run `ghapp-token install-git` again and check `git config --global --get-all credential.https://github.com.helper`. |
