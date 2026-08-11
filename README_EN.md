# Proxy Audit

[简体中文](README.md) | [English](README_EN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Security and tests](https://github.com/zouchenzhen/proxy-audit/actions/workflows/security-and-tests.yml/badge.svg)](https://github.com/zouchenzhen/proxy-audit/actions/workflows/security-and-tests.yml)

Proxy Audit is a Web UI for batch-testing proxy node connectivity and exit-IP quality. Its localhost Windows edition is available now, and a browser-ready Hugging Face demo is in preparation. It imports v2rayN backups, databases, subscriptions, and share links; runs real outbound checks through sing-box or Xray; enriches exit IPs with multiple intelligence providers; and presents searchable, filterable results.

> [!IMPORTANT]
> Test only assets that you own, manage, or have explicit permission to test. Follow applicable local laws and third-party service terms. Proxy Audit is not a node provider and does not offer a public proxy service, access-control bypass, or anonymity guarantee.

## Online demo (coming soon)

Online address (not open yet): [https://zouchenzhen-zcz.hf.space](https://zouchenzhen-zcz.hf.space)

> [!NOTE]
> I am developing a browser-ready demo that will require no local installation. I will update its
> availability here after stability and privacy validation; use the local edition in the meantime.

The online demo will run its page and audit backend in the same ephemeral cloud environment. After
explicit consent, each browser tab will receive an anonymous temporary session and upload nodes,
subscriptions, API keys, tasks, and results to that temporary backend.

- Proxy Audit keeps that data in one process's memory and task-scoped temporary files, not a database.
- A session lasts at most one hour. Expiry or manual deletion invalidates it immediately and triggers
  cancellation and cleanup; an in-flight network request may take up to its 12-second timeout to exit.
- Space restart, sleep, or redeployment destroys all sessions, so export results immediately.
- Each import/task is limited to 20 nodes, concurrency to 2, and each client network to 100 nodes/day.
- Hugging Face and the selected subscription/intelligence/probe services still process data required
  for the request. Use the local edition for sensitive, large, or persistent workloads.

Before the demo opens, these rules may be adjusted based on validation results and the documentation
will be updated accordingly. The deployed site will expose upstream licenses and corresponding-source
archives for the pinned sing-box and Xray builds under `/third-party/`.

API keys can be registered on each provider's official website. Free plans are generally sufficient
for low-volume personal use; current quotas and terms are determined by each provider. Providers that
do not require a key can also be used directly.

## Local edition quick start

Windows 11 and Python 3.10+ are recommended.

```powershell
git clone https://github.com/zouchenzhen/proxy-audit.git
cd proxy-audit
.\start-web.cmd
```

The launcher creates a virtual environment, installs Python dependencies, and downloads a pinned sing-box release with SHA256 verification when no supported core is found. The browser then opens `http://127.0.0.1:8765`. The server listens on localhost only.

You can also start it from PowerShell:

```powershell
.\start-web.ps1
```

## Highlights

- Import v2rayN backup ZIP files, `guiNDB.db`, subscription URLs, and share links
- Preview imported nodes before running checks
- Use sing-box or Xray, with protocol-aware compatibility filtering
- Select all nodes or any filtered subset for a batch run
- Query ipify, ip-api, ipapi.is, IPinfo, IP2Location, IPQualityScore, Scamalytics, and AbuseIPDB
- Store multiple API keys per provider and rotate automatically when a key is unavailable or rate-limited
- Search and filter by status, protocol, country, IP type, native-IP judgment, risk, and service reachability
- Preserve recent task history, restore task-specific metrics/results, and rename tasks
- Switch between dark, light, and system themes, with three interface font sizes
- Export sanitized JSON, CSV, and Markdown reports
- Optionally probe ChatGPT, Claude, GitHub, and YouTube endpoints; these probes are disabled by default and do not affect the default quality score

## Screenshots

All screenshots below were generated in an isolated acceptance environment with synthetic `.invalid` nodes. They contain no real subscriptions, credentials, exit IPs, or complete API keys.

![Proxy Audit dark dashboard](docs/assets/dashboard-dark-demo.png)

![Proxy Audit authorization and partial selection](docs/assets/authorization-gate-demo.png)

<details>
<summary>Light theme</summary>

![Proxy Audit light dashboard](docs/assets/dashboard-light-demo.png)

</details>

## API keys, privacy, and security

- On Windows, Web UI secrets are stored in `config.secure.json` using DPAPI for the current user.
- The API never returns a complete saved key to the browser. The eye button reveals only a short prefix for identification.
- Node credentials are used only in memory and one-time core configurations, which are deleted after each check.
- New Web tasks remove UUIDs, passwords, subscription URLs, and log tails from saved and exported results.
- The online demo will upload operational data to its ephemeral backend; it will not persist a project database or include third-party analytics SDKs. The local edition does not send that data to a Proxy Audit backend.
- Both editions contact selected subscription servers, intelligence providers, and probe endpoints. Keep the local panel on `127.0.0.1` and do not expose it through a public tunnel.

See [Privacy](PRIVACY.md), [Security Policy](SECURITY.md), and [Responsible Use](COMPLIANCE.md) for details. Never publish real subscriptions, node credentials, API keys, or identifiable result data in issues, pull requests, logs, or screenshots.

For optional process-only injection with 1Password CLI, copy `config.1password.example.env` to
`.1password/proxy-audit.env`, replace the placeholders with `op://` references, and run
`./start-web-1password.ps1`. The profile stores references only. Runtime keys are not copied into
`config.secure.json` when other settings are saved through the UI.

IP-API's free endpoint requires neither registration nor a key. IP-API and ipapi.is are separate
providers: an ipapi.is key is optional, and the anonymous free tier remains available when it is
left blank. Registered users can copy the key shown under `API Credentials` into the settings
panel. Scamalytics sends the API username, key, documentation, and access details after reviewing
the registration request.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python scripts/scan_git_history.py
python tests/ui_browser_acceptance.py
python tests/ui_online_acceptance.py --url "https://zouchenzhen-zcz.hf.space/"
```

Browser acceptance uses a temporary headless Chrome profile. It exercises settings, import preview, authorization confirmation, partial selection, task history, filtering, themes, and layout checks without touching your normal browser profile.

An optional privacy-safe live-network sampler is also available:

```powershell
python tests/real_local_acceptance.py --db "C:\path\to\v2rayN\guiConfigs\guiNDB.db"
```

## Scope and limitations

- A successful result means the generated core configuration and outbound path worked during that run. It does not prove that a node will remain online or is suitable for every service.
- Intelligence providers use different definitions for risk, proxy, hosting, and residential networks. Review the raw provider fields when the distinction matters.
- ChatGPT, Claude, GitHub, and YouTube probes report endpoint reachability only; they do not guarantee account availability, regional eligibility, or freedom from platform risk controls.
- Third-party subscriptions, IP intelligence APIs, test endpoints, sing-box, and Xray remain subject to their own terms and licenses.

## Community

[LINUX DO — Chinese Developer Community](https://linux.do/)

This project recognizes and appreciates LINUX DO's contribution to open-source exchange, project sharing, and technical discussion among Chinese-speaking developers. Unless the community explicitly states otherwise, this is an acknowledgment and link only, not an official endorsement.

## License and third-party software

Original project code is licensed under the [Apache License 2.0](LICENSE), including its patent grant and NOTICE requirements.

sing-box (GPL-3.0-or-later), Xray-core (MPL-2.0), Python packages, and external IP intelligence services are independent third-party components and are not relicensed under Apache-2.0. The source repository does not commit core binaries; the HF image redistributes pinned builds together with upstream licenses and corresponding source archives. See [Third-Party Notices](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE), and [Trademark Policy](TRADEMARKS.md).
