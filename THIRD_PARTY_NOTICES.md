# 第三方软件与服务说明

本文件用于归属和合规提示，不改变 `proxy_audit` 自有代码的 Apache-2.0 许可。
第三方软件、库、服务和商标仍分别受其权利人的许可证、服务条款及商标规则约束。

## 检测内核

| 组件 | 本项目中的关系 | 上游许可证 |
|---|---|---|
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | 未提交到 Git；首次启动可从上游 Release 独立下载固定版本 1.13.3，并校验 SHA256；以独立子进程运行 | GPL-3.0-or-later；以其上游 `LICENSE` 为准 |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | 未提交、未自动分发；仅在用户自行安装或从 v2rayN 中发现后，以独立子进程运行 | MPL-2.0；以其上游 `LICENSE` 为准 |

本仓库的 Apache-2.0 不覆盖上述内核。仅从源码克隆本仓库时不会从 Git 获得这些
二进制。如果重新打包、镜像或随产品分发内核，分发者必须自行履行相应许可证义务，
包括但不限于保留许可证/版权声明以及 GPL 场景下适用的完整对应源码义务。

## Python 运行时依赖

`requirements.txt` 的直接依赖为 Flask（BSD-3-Clause）与 Requests
（Apache-2.0）；Requests 的 SOCKS 支持使用 PySocks（BSD-3-Clause）。安装时还会解析
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
