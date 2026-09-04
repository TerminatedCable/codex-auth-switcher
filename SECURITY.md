# Security

## Supported versions

Security fixes are provided for the latest release. Use GitHub's private vulnerability reporting for sensitive reports. Never attach real Codex credentials, account identifiers, DPAPI files, or unredacted diagnostic output.

## Security model

`auth.json` is a password-equivalent credential file. Codex must read its active copy in plaintext. Saved account and rollback snapshots are encrypted with Windows DPAPI in `CurrentUser` scope and additional application entropy.

The switcher:

- makes no network requests;
- executes no downloaded or dynamic code;
- accepts only restricted account labels;
- refuses elevation, keyring/auto credential modes, and reparse-point paths;
- closes only a verified packaged Codex process and never force-kills it;
- writes through a same-directory temporary file with the existing auth ACL;
- verifies the account identity after atomic replacement and restores on verification failure;
- writes no persistent logs and never outputs credential values.

The GitHub workflow uses no third-party actions, grants only `contents: read`, fetches the exact event commit, and runs the repository's dependency-free tests.

## Residual risks

- Malware running as the same Windows user or an administrator can read live Codex credentials and can ask DPAPI to decrypt saved credentials.
- A compromised Windows account, operating system, PowerShell installation, Codex installation, or downloaded copy of this script defeats the local protections.
- The active `auth.json` remains plaintext, as required by file-backed Codex authentication.
- DPAPI snapshots are tied to the Windows user/security context and are not a portable backup.
- A power loss or filesystem failure can still damage files; atomic replacement and encrypted rollback reduce but cannot eliminate that risk.
- The tool cannot prove that an unspecified Codex default is file-backed merely from documentation. It refuses explicit `keyring` or `auto` modes and requires a valid live `auth.json`; verify the selected account in the Codex UI after first use.

## Audit notes for v0.1.0

The initial review covers credential validation, DPAPI use, secret output, path traversal and reparse points, concurrent execution, process identity and shutdown, atomic replacement and rollback, network primitives, dynamic execution, workflow permissions, and preservation of non-auth Codex files. No claim of zero risk is made.
