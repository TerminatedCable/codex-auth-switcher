# Codex Auth Switcher for Windows

A tiny, source-only account switcher for the native Codex Windows app. It preserves one shared Codex home and changes only the active `auth.json`, so settings, sessions, history, skills, plugins, and projects stay in place.

## What it does

- Saves named account snapshots with Windows DPAPI (`CurrentUser`).
- Preserves the departing account's latest refreshed tokens before every switch.
- Atomically replaces `%USERPROFILE%\.codex\auth.json` and keeps an encrypted rollback.
- Gracefully closes and reopens Codex when it was running.
- Makes no network requests and has no packages, installer, telemetry, self-update, or compiled binary.

Codex officially supports credentials in either `auth.json` or the operating-system credential store. This tool intentionally supports only file-backed ChatGPT authentication and never changes `config.toml`. See [OpenAI's authentication documentation](https://learn.chatgpt.com/docs/auth) and [Windows app documentation](https://learn.chatgpt.com/docs/windows/windows-app).

## Requirements

- Windows 10 or 11
- Native Codex app from the Microsoft Store
- Windows PowerShell 5.1
- ChatGPT login stored in `%CODEX_HOME%\auth.json` or `%USERPROFILE%\.codex\auth.json`

Run the tool as your normal Windows user, not as Administrator.

## Install

Download the source release, verify its SHA-256 checksum, and extract it to a folder you control. No system installation is required.

The `codex-auth.cmd` launcher uses `-ExecutionPolicy Bypass` for that PowerShell process only. It does not modify your user or machine execution policy.

## First-time setup

With your first account active in Codex:

```bat
codex-auth save "Account 1"
```

Use Codex's normal sign-out/sign-in flow to authenticate the second account, then save it:

```bat
codex-auth save "Account 2"
```

The app closes briefly while a stable credential snapshot is captured and reopens if it was running.

## Use

```bat
codex-auth list
codex-auth switch "Account 1"
codex-auth switch "Account 2"
codex-auth restore
```

Run `codex-auth` without arguments for a numbered picker. An asterisk in `list` marks the account matching the live `auth.json`.

Labels are local aliases. Use 1-32 ASCII letters or numbers, with spaces, dots, underscores, or hyphens allowed between them. Labels must begin and end with a letter or number.

## Storage and privacy

| Data | Location | Protection |
| --- | --- | --- |
| Active Codex login | `%CODEX_HOME%\auth.json` | Codex's normal plaintext format and existing ACL |
| Saved accounts | `%LOCALAPPDATA%\TerminatedCable\CodexAuthSwitcher\accounts\*.auth.dpapi` | Windows DPAPI, current user |
| Last rollback | `%LOCALAPPDATA%\TerminatedCable\CodexAuthSwitcher\rollback.auth.dpapi` | Windows DPAPI, current user |

The tool never prints or logs emails, tokens, account IDs, or usage information. DPAPI does not protect against malware already running as your Windows user, an administrator, or a fully compromised computer. Read [SECURITY.md](SECURITY.md) before use.

## Important boundary

Use only accounts you own or are authorized to use, and comply with OpenAI's applicable terms. This project does not inspect limits or automatically rotate accounts when quota is exhausted. Reddit users have also described limit-driven switching as a [terms gray area](https://www.reddit.com/r/codex/comments/1w0zvjh/i_know_we_all_hate_the_limit_but_i_was_able_to/).

## Development

The repository has no dependencies. On Windows:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
```

The test suite uses synthetic credentials and temporary directories. Never use real `auth.json` files in tests, bug reports, issues, or pull requests.

## Background

This is an original, deliberately smaller implementation informed by public work in [Loongphy/codex-auth](https://github.com/Loongphy/codex-auth) and [Chisiki1/codex-account-switcher-windows](https://github.com/Chisiki1/codex-account-switcher-windows). No upstream runtime, package, or downloaded executable is included.

This project is unofficial and is not affiliated with or endorsed by OpenAI.
