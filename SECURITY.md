# Security Policy

## Supported version

Security fixes target the latest commit on the default branch. Old commits, unofficial packages,
forks, modified detection cores, unofficial public deployments and third-party services are not
maintained by this project.

## Reporting a vulnerability

Please use GitHub's **Security → Report a vulnerability** private reporting flow for this repository.
If private reporting is temporarily unavailable, open a public Issue containing only a request for a
private contact channel—do not include exploit details, subscription URLs, node credentials, API keys,
real IP addresses or logs.

Useful private reports include affected commit/version, impact, minimal reproduction using synthetic
data, and a proposed mitigation. Reports are handled on a best-effort basis; no fixed response or
bounty commitment is made.

## Security boundaries

- The local Web UI must remain bound to `127.0.0.1`/localhost. It has no authentication layer and is
  not a production WSGI service.
- The official HF edition uses high-entropy sessions, a one-hour maximum lifetime, strict node and
  concurrency quotas, public-address-only targets, pinned DNS resolution, upload/ZIP limits,
  same-origin API checks and one WSGI process. Do not remove those controls from a public deployment.
- Only test nodes you own or are explicitly authorized to test.
- Node links and archives are untrusted input. Keep the project and generated files in a restricted
  local directory and use an unprivileged Windows account.
- Saved API keys use Windows DPAPI for the current user. Legacy `config.local.json` is plaintext.
- Temporary core configurations are deleted after a task, but crash dumps, backups, endpoint logs,
  antivirus products or privileged local software may still retain data.
- Downloaded or distributed core archives are pinned and SHA256-verified. Do not replace either
  binary with an untrusted build.
- Never expose this local panel using port forwarding, reverse proxies, Cloudflare Tunnel, ngrok or
  similar tooling without first adding authentication, authorization, TLS, CSRF protection, rate
  limits, audit logging and a complete deployment security review.

## Contribution hygiene

Run these checks before opening a pull request:

```powershell
python -m unittest discover -s tests -v
python scripts/scan_git_history.py
```

Use only RFC 5737 documentation IP ranges, `example.com`/`example.invalid`, synthetic UUIDs and fake
keys in tests and screenshots. See `COMPLIANCE.md`, `PRIVACY.md` and `THIRD_PARTY_NOTICES.md`.
