# Omanas

Your Synology NAS in the Omarchy bar — health, storage, live resources, recent
logs, and one-click mounting of shared folders.

> **Status: early development.** Not yet ready to install.

## What it does

Click the bar icon and you get roughly what DSM shows you in its own sidebar
when you log in:

- **System health** — model, DSM version, uptime, temperature, fan state
- **Storage** — per-volume usage, pool status, disk health
- **Resources** — live CPU, memory and network graphs while the panel is open
- **Logs** — the most recent system log entries
- **Shared folders** — list every share, mount it locally, unlock it if it is
  encrypted

## Requirements

- Omarchy 4.x (Quickshell-based shell with the plugin API)
- A Synology NAS running DSM 7, reachable at a hostname or IP on your network
- `python` (standard library only — no pip install)
- `libsecret` / `secret-tool` for credential storage, and a running keyring
- `cifs-utils` for mounting shared folders

## Authentication

DSM has no long-lived API token for the endpoints this needs, so Omanas signs
in the way the DSM web UI does: it posts your username and password to
`SYNO.API.Auth` and keeps the returned session id. Two-factor accounts are
supported — Omanas asks for the code once and stores DSM's device token so it
does not ask again on the same machine.

Your password and device token go into your **system keyring** via
`secret-tool`. They are never written to `shell.json`, never passed on a
command line, and never held in the shell's QML scene, which third-party
plugins share. Non-secret settings (host, port, username) live in
`~/.config/omanas/config.json`.

For a NAS using a self-signed certificate, Omanas pins the certificate
fingerprint the first time you connect and warns you if it ever changes,
rather than turning verification off.

Most of the health, resource and log endpoints require an account in the
**administrators** group. A non-admin account still works; the panel just
shows less.

### Two-factor accounts

Signing in with 2FA takes two round trips: the first is refused with "code
required", and the second carries the code. Omanas asks for the code in the
same form, keeps the password you already typed across that gap, and puts the
code field back when DSM says a code was wrong rather than making you start
over. On success it stores DSM's device token, so the same machine is not
asked again.

## Mounting shared folders

Mounts are on demand by default. Clicking *Mount* runs a small root helper
through `pkexec`, so you get Omarchy's polkit dialog; polkit caches that
authorisation for a few minutes, so mounting several shares in a row asks
once. Shares land under `~/mnt/nas/<share>` as real kernel CIFS mounts, so
every application sees them — terminal, editor and file manager alike.

Flip **Keep this share** and Omanas adds an `/etc/fstab` entry with
`noauto,user`. That costs one authorisation now and makes every later mount of
that share prompt-free, because Arch ships `mount.cifs` setuid. Entries live
inside a marked, managed block; removing the share removes its line and
nothing else.

Omanas deliberately does **not** install a polkit rule granting passwordless
mounts. That would be a permanent privilege grant on your machine for the
convenience of one plugin. If you want it on a single-user machine, the
README documents how — it stays your decision, not the installer's.

## Encrypted shared folders

"Unlock" here means unlocking the share **on the NAS**, the same as DSM's own
*Mount* action for an encrypted shared folder: Omanas sends the encryption
passphrase to `SYNO.Core.Share.Crypto`, DSM decrypts it, and the share becomes
readable. The passphrase travels to the helper over stdin and is not stored
unless you ask Omanas to remember it in the keyring.

## Developing

```bash
ln -s ~/Work/omanas ~/.config/omarchy/plugins/io.github.mr-benedict.omanas
omarchy-shell shell rescanPlugins
omarchy plugin enable io.github.mr-benedict.omanas --section right
python3 -m unittest discover -s tests
```

Note that the shell's plugin hot-reload does **not** follow a symlinked
plugin directory. While developing through a symlink, `omarchy restart shell`
is what actually picks up a change; a `rescanPlugins` will appear to succeed
while the old code keeps running.

### Tests

Standard library only, so there is nothing to install:

```bash
python3 -m unittest discover -s tests          # everything
python3 tests/test_dsm_client.py               # one file, verbosely
```

Nothing in the suite touches a network, a keyring or `/etc/fstab`; the
transport is faked and the paths are redirected into a scratch directory, so
it is safe to run on a machine with a working install.

Python 3.12 or newer. The floor is `bin/omanas-mount`, which puts a backslash
inside an f-string expression — a syntax error before 3.12.

### What CI checks on a pull request

- The suite, on Python 3.12 and 3.13, with deprecation warnings fatal.
- `ruff check` — errors only (undefined names, unused imports), no style
  rules. An undefined name on a path no test reaches is the one class of bug
  the suite genuinely cannot see.
- That no credential file or private key is committed, that the two helpers
  keep their executable bit, and that commit messages carry no assistant
  co-author trailers.

Run the first two before opening a PR and there should be no surprises.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
