# Cloudflare Pages redirect

`https://proxy-audit.pages.dev` will become a compatibility entry point after the Hugging Face Space
is manually unblocked. The bundle contains no application, Worker, Pages Function, storage binding,
analytics, or user data processing. `_redirects` then sends all paths to:

`https://zouchenzhen-zcz.hf.space`

Do not deploy this redirect while the Space carries the inherited 2025 abuse suspension.

Build and deploy:

```powershell
python scripts/build_pages.py
npx wrangler@latest pages deploy pages-dist --project-name proxy-audit --branch main
```
