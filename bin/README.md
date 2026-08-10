# sing-box runtime

`start-web.cmd` downloads the pinned Windows `sing-box` release from the official GitHub release page when the executable is missing, and verifies its SHA256 before use.

For a manual/offline installation, place the executable at:

```text
bin/sing-box.exe
```

Runtime binaries and downloaded archives are intentionally excluded from Git.
sing-box remains licensed by its upstream authors under GPL-3.0-or-later plus
the terms in its upstream `LICENSE`; Xray-core remains MPL-2.0. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) before redistributing a
binary bundle.
