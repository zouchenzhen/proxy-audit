# Cloudflare Pages deployment

The public site is a static copy of `web/`. It has no Pages Functions, Worker API, KV, D1, R2,
analytics script, or server-side secret storage. Browser requests containing nodes, subscriptions,
API keys, settings, tasks, or results are sent only to the user's local engine at
`http://127.0.0.1:8765`.

Build and deploy:

```powershell
python scripts/build_pages.py
npx wrangler@latest pages deploy pages-dist --project-name proxy-audit --branch main
```

The production origin is `https://proxy-audit.pages.dev`. The local Flask engine only allows CORS
from that exact origin. Preview deployment hostnames intentionally cannot access the local API.

The CSP in `_headers` restricts `connect-src` to the local engine. Do not add Cloudflare Functions,
third-party analytics, remote scripts, or a cloud API without updating the privacy documentation and
making the architectural change explicit to users.
