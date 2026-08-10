# 第三方软件与服务说明

本文件用于归属和合规提示，不改变 Proxy Audit 自有代码的 Apache-2.0 许可。
第三方软件、库、服务和商标仍分别受其权利人的许可证、服务条款及商标规则约束。

## 检测内核

| 组件 | 本项目中的关系 | 上游许可证 |
|---|---|---|
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | 不提交二进制到 Git；本地启动可下载固定版本 1.13.3；HF 镜像分发 1.13.3 Linux 构建、上游许可证和对应源码归档；均校验 SHA256 并以独立子进程运行 | GPL-3.0-or-later；以上游 `LICENSE` 为准 |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | 不提交二进制到 Git；本地版由用户提供/自动发现；HF 镜像分发 26.3.27 Linux 构建、上游许可证和对应源码归档；校验 SHA256 并以独立子进程运行 | MPL-2.0；以上游 `LICENSE` 为准 |

本仓库的 Apache-2.0 不覆盖上述内核。仅从源码克隆本仓库时不会从 Git 获得二进制。
官方 HF 镜像在 `/opt/proxy-audit/third-party/` 保留许可证及对应固定版本源码归档。其他
重新打包、镜像或分发者仍须自行履行相应许可证义务。

## Python 运行时依赖

`requirements.txt` 的直接依赖为 Flask（BSD-3-Clause）与 Requests（Apache-2.0）；
`requirements-cloud.txt` 另加入 Gunicorn（MIT）。Requests 的 SOCKS 支持使用 PySocks
（BSD-3-Clause）。安装时还会解析
下列传递依赖。具体版本由安装时间和版本范围决定，重新分发环境时应以实际安装包内
的元数据和许可证文件为准。

| 组件 | 常见许可证 |
|---|---|
| Flask、Werkzeug、Jinja2、Click、ItsDangerous、MarkupSafe | BSD-3-Clause |
| Requests | Apache-2.0 |
| PySocks | BSD-3-Clause |
| Blinker、urllib3、charset-normalizer | MIT |
| Certifi | MPL-2.0 |
| idna、colorama | BSD-3-Clause |

开发/验收依赖 `websocket-client` 使用 Apache-2.0。Python 解释器本身不随本仓库分发，
其许可证以 [Python Software Foundation](https://docs.python.org/3/license.html) 为准。

## 外部数据与网络服务

项目可以按用户选择访问 ipify、IP-API、ipapi.is、IPinfo、IP2Location、
IPQualityScore、Scamalytics、AbuseIPDB，以及可选的 ChatGPT、Claude、GitHub、
YouTube 测试端点。这些是独立服务，不是本项目的一部分。用户必须自行检查并遵守
各服务最新条款、隐私政策、API 额度、自动化访问限制和商标规则。

## 商标

sing-box、Xray、v2rayN、GitHub、ChatGPT、Claude、YouTube 及其他名称可能是其
各自权利人的商标。引用仅用于说明兼容性，不表示授权、背书或关联。
