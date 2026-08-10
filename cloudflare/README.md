# Cloudflare Pages redirect

`https://proxy-audit.pages.dev` is an optional compatibility entry point for the hosted demo. The
bundle contains no application, Worker, Pages Function, storage binding, analytics, or user data
processing. `_redirects` sends all paths to:

`https://zouchenzhen-zcz.hf.space`

Deploy the redirect only after the target has been opened publicly and its health and privacy behavior
have been verified.

Build and deploy:

```powershell
python scripts/build_pages.py
npx wrangler@latest pages deploy pages-dist --project-name proxy-audit --branch main
```
