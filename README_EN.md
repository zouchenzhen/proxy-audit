# Proxy Audit

[简体中文](README.md) | [English](README_EN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Security and tests](https://github.com/zouchenzhen/proxy-audit/actions/workflows/security-and-tests.yml/badge.svg)](https://github.com/zouchenzhen/proxy-audit/actions/workflows/security-and-tests.yml)

Proxy Audit is a local Windows application for batch-testing proxy node connectivity and exit-IP quality. It imports v2rayN backups, databases, subscriptions, and share links; runs real outbound checks through sing-box or Xray; enriches exit IPs with multiple intelligence providers; and presents searchable, filterable results in a Web UI.

> [!IMPORTANT]
> Test only assets that you own, manage, or have explicit permission to test. Follow applicable local laws and third-party service terms. Proxy Audit is not a node provider and does not offer a public proxy service, access-control bypass, or anonymity guarantee.

## Online UI

Open: [https://proxy-audit.pages.dev](https://proxy-audit.pages.dev)

Cloudflare Pages serves static HTML, CSS, and JavaScript only. There is no Proxy Audit cloud API,
database, telemetry, or analytics endpoint receiving your nodes, subscriptions, API keys, or results.
The full audit still runs in the local engine at `127.0.0.1:8765`, so start `start-web.cmd` on your PC
first. Chrome or Edge may ask you to allow local-network access when connecting for the first time.

Cloudflare necessarily processes ordinary metadata needed to serve the static page. Subscription
servers, enabled IP-intelligence providers, and optional probe endpoints still receive the data needed
to answer their requests; these are not Proxy Audit cloud services.

API keys can be registered on each provider's official website. Free plans are generally sufficient
for low-volume personal use; current quotas and terms are determined by each provider. Providers that
do not require a key can also be used directly.

## Quick start

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
- The project has no official cloud account, advertising, or telemetry. Checks are not fully offline: subscription servers, enabled IP intelligence providers, and optional probe endpoints receive the network data required to answer each request.
- Keep the panel on `127.0.0.1`; do not expose it through port forwarding, a reverse proxy, or a public tunnel.

See [Privacy](PRIVACY.md), [Security Policy](SECURITY.md), and [Responsible Use](COMPLIANCE.md) for details. Never publish real subscriptions, node credentials, API keys, or identifiable result data in issues, pull requests, logs, or screenshots.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python scripts/scan_git_history.py
python tests/ui_browser_acceptance.py
python tests/ui_online_acceptance.py
```

The browser acceptance test launches an isolated local backend and a temporary headless Chrome profile. It exercises settings, import preview, authorization confirmation, partial selection, task history, filtering, themes, and layout checks without touching your normal browser profile.

An optional privacy-safe live-network sampler is also available:

```powershell
python tests/real_local_acceptance.py --db "E:\path\to\v2rayN\guiConfigs\guiNDB.db"
```

## Scope and limitations

- A successful result means the generated core configuration and outbound path worked during that run. It does not prove that a node will remain online or is suitable for every service.
- Intelligence providers use different definitions for risk, proxy, hosting, and residential networks. Review the raw provider fields when the distinction matters.
- ChatGPT, Claude, GitHub, and YouTube probes report endpoint reachability only; they do not guarantee account availability, regional eligibility, or freedom from platform risk controls.
- Third-party subscriptions, IP intelligence APIs, test endpoints, sing-box, and Xray remain subject to their own terms and licenses.

## License and third-party software

Original project code is licensed under the [Apache License 2.0](LICENSE), including its patent grant and NOTICE requirements.

sing-box (GPL-3.0-or-later), Xray-core (MPL-2.0), Python packages, and external IP intelligence services are independent third-party components and are not relicensed under Apache-2.0. The official repository does not distribute core binaries. See [Third-Party Notices](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE), and [Trademark Policy](TRADEMARKS.md).
