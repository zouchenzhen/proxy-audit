# proxy_audit

Windows 11 下的代理节点批量检测工具。目标是从 v2rayN 备份 / 数据库 / 分享链接中读取节点，使用 sing-box 建立本地代理并真实出站测试，查询出口 IP 的多源情报，最后输出可读报表。

## Web UI（推荐）

双击项目根目录的 `start-web.cmd`，或者在 PowerShell 中运行：

```powershell
cd E:/Openclaw_Workspace/proxy_audit
./start-web.ps1
```

浏览器会打开 `http://127.0.0.1:8765`。面板只监听本机，不对局域网或公网开放。

Web UI 现已支持：

- 粘贴分享链接、Base64 订阅正文、订阅 URL、TXT、v2rayN 备份 ZIP、`guiNDB.db`
- 自动解析 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC、AnyTLS
- 在 sing-box 与 Xray 两个检测内核之间选择，并显示本机可用状态
- 控制并发数、超时、节点上限以及运行前关键字筛选
- 自选 IP-API、ipapi.is、IPinfo、IP2Location、IPQS、Scamalytics、AbuseIPDB
- 后台任务进度、取消、事件流、结果搜索和多维筛选
- 安全导出 CSV、JSON、Markdown；导出结果不会包含 UUID、密码或订阅地址
- 可选延迟/抖动采样，以及默认关闭的 ChatGPT、Claude、GitHub、YouTube 端点探测

> ChatGPT / Claude 等探测只说明指定端点可以访问，不等于账号可用、地区解锁或风控安全，因此不会参与默认质量评分。

### Key 与节点凭据安全

- 在 Web 设置中保存的 Key 会写入 `config.secure.json`；Windows 下使用当前用户 DPAPI 加密。
- API 不会把已保存的 Key 回传给浏览器，只显示“已配置”状态。
- 每个节点的临时内核配置会在检测后删除。
- Web 新任务保存的 raw/CSV/Markdown 都会剔除 UUID、密码、订阅 URL 和日志尾部。
- `config.local.json` 是旧版明文配置兼容入口。确认新设置已经保存后，建议手动删除旧文件。
- `input/`、`results/`、`temp/`、本地配置和内核二进制均已加入 `.gitignore`。

### 安装依赖

启动脚本会检查依赖。也可以手动安装：

```powershell
python -m pip install -r requirements.txt
```

运行测试：

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tests/ui_browser_acceptance.py
python tests/real_local_acceptance.py --db "E:\\path\\to\\v2rayN\\guiConfigs\\guiNDB.db"
```

最后一条是可选的真实网络验收：默认每个“内核 × 协议”抽样 3 个节点，仅调用
`ip-api`，且不会输出节点名称、服务器、凭据、订阅地址或出口 IP。节点过期或离线
会被单独记为节点/上游不可达，不能据此直接判定解析器或内核适配失败。

第二条命令会启动隔离的本地后端和无头 Chrome，真实点击设置、导入、任务、筛选等 UI，并检查布局是否溢出或重叠。

## 当前能力与验收边界

2026-08-08 使用本机当前 v2rayN 数据库做过隐私安全的抽样验收：

| 协议 | sing-box | Xray | 本轮真实出口 |
|---|---|---|---|
| VLESS | 配置校验通过 | 配置校验通过 | 双内核成功 |
| VMess | 配置校验通过 | 配置校验通过 | 双内核成功 |
| Trojan | 配置校验通过 | 配置校验通过 | 抽样节点均不可达 |
| Shadowsocks | 配置校验通过 | 配置校验通过 | 抽样节点均不可达；插件传输暂不支持 |
| Hysteria2 | 配置校验通过 | 不支持 | sing-box 成功 |
| TUIC | 配置校验通过 | 不支持 | sing-box 成功 |
| AnyTLS | 配置校验通过 | 不支持 | 本轮抽样节点不可达；历史批次有成功样本 |

“配置校验通过”表示已安装内核真实接受生成的 JSON，不等于任意第三方节点一定在线。
完整、去标识化的验收记录见 `docs/acceptance-2026-08-08.md`。

已接入的 IP 情报源：
- ipify
- ip-api
- ipapi.is
- IPinfo
- IP2Location
- IPQualityScore (IPQS)
- Scamalytics
- AbuseIPDB（需要 Key，可选）

统一输出字段包括：
- `ip_type_final`
- `risk_score_final`
- `risk_level_final`
- `native_ip_judgement`

## 目录结构

```text
proxy_audit/
├─ bin/
│  ├─ sing-box.exe
│  └─ xray.exe                 # 可选，也可在 Web 设置中指定
├─ web/
│  ├─ index.html
│  ├─ styles.css
│  └─ app.js
├─ scripts/
│  ├─ web_app.py
│  ├─ proxy_audit_batch.py
│  ├─ lib_v2rayn.py
│  ├─ lib_kernels.py
│  ├─ lib_runner.py
│  ├─ lib_tasks.py
│  ├─ lib_ipintel.py
│  ├─ lib_secrets.py
│  └─ lib_report.py
├─ tests/
├─ start-web.cmd
├─ start-web.ps1
├─ requirements.txt
├─ config.secure.json          # 本机生成，不进入 Git
├─ README.md
├─ CHANGELOG.md
├─ results/
│  ├─ raw/
│  ├─ csv/
│  └─ reports/
└─ temp/
   ├─ configs/
   ├─ logs/
   └─ backup_extract/
```

## 环境要求

- Windows 11
- Python 3.x
- `<项目目录>/bin/sing-box.exe`，或在 Web 设置中指定路径
- Xray 为可选第二内核；可放入 `bin/xray.exe` 或指定现有 v2rayN 内核路径
- 可访问外网
- 推荐在 Web 设置中填写多源情报 API Key

推荐先进入项目目录：

```powershell
cd E:/Openclaw_Workspace/proxy_audit
```

## 配置文件

### Web 加密设置（推荐）

设置面板会生成 `config.secure.json`。Windows 下内容由 DPAPI 加密，只能由当前 Windows 用户解密。

### `config.local.json`（旧版兼容）

示例：

```json
{
  "ip2location_api_key": "...",
  "ipinfo_api_key": "...",
  "ipqs_api_key": "...",
  "scamalytics_user": "...",
  "scamalytics_api_key": "...",
  "abuseipdb_api_key": "..."
}
```

作用：
- 为多源 IP 画像提供正式 API key
- 主流程和增强脚本都会读取它

## 输入源

### 1. v2rayN 备份 ZIP

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip"
```

### 2. v2rayN 数据库 `guiNDB.db`

```powershell
python scripts/proxy_audit_batch.py --v2ray-db "E:/path/to/guiNDB.db"
```

### 3. 分享链接文件

```powershell
python scripts/proxy_audit_batch.py --input-file "E:/path/to/nodes.txt"
```

## 常用运行方式

### 全量运行所有节点

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip"
```

### 只跑某个协议

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols vless
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols vmess
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols anytls
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols hysteria2
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols tuic
```

### 同时跑多个协议

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols vless,vmess,anytls,hysteria2,tuic
```

### 小批量验证

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --protocols vmess --limit 5
```

### 按关键词筛选

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --filter-substring "JP"
```

### 指定起始端口 / 超时

```powershell
python scripts/proxy_audit_batch.py --v2ray-backup "E:/backup/v2ray_backup_26_0319.zip" --start-port 22080 --timeout 20
```

## 输出文件位置

每次运行都会生成一组时间戳文件：

- 原始 JSON：`results/raw/run_YYYYMMDD_HHMMSS.json`
- CSV：`results/csv/run_YYYYMMDD_HHMMSS.csv`
- Markdown：`results/reports/run_YYYYMMDD_HHMMSS.md`

内容包括：节点信息、出站测试结果、出口 IP、多源情报、统一画像字段、错误信息等。

## 对已有结果补画像

```powershell
python scripts/enhance_existing_run.py --input-raw "E:/Openclaw_Workspace/proxy_audit/results/raw/run_20260319_201919.json"
```

## 生成成功节点汇总与 shortlist

```powershell
python scripts/generate_success_reports.py --stamp 20260320_1434
```

输出文件会自动带上当前统计数量，例如：
- `success_nodes_full_53_20260320_1434.json`
- `success_nodes_full_53_20260320_1434.csv`
- `success_nodes_shortlist_34_20260320_1434.json`
- `success_nodes_shortlist_34_20260320_1434.csv`

## 当前重要结果文件

### VLESS 增强画像结果
- `E:/Openclaw_Workspace/proxy_audit/results/raw/run_20260319_201919_enhanced.json`
- `E:/Openclaw_Workspace/proxy_audit/results/csv/run_20260319_201919_enhanced.csv`
- `E:/Openclaw_Workspace/proxy_audit/results/reports/run_20260319_201919_enhanced.md`

### 成功有效节点总表（最新稳定版）
- `E:/Openclaw_Workspace/proxy_audit/results/reports/success_nodes_full_53_20260320_1434.json`
- `E:/Openclaw_Workspace/proxy_audit/results/reports/success_nodes_full_53_20260320_1434.csv`

### 成功节点 shortlist（最新稳定版）
- `E:/Openclaw_Workspace/proxy_audit/results/reports/success_nodes_shortlist_34_20260320_1434.json`
- `E:/Openclaw_Workspace/proxy_audit/results/reports/success_nodes_shortlist_34_20260320_1434.csv`

## 当前支持状态

### 已有真实成功样本
- VLESS
- VMess
- AnyTLS
- Hysteria2

### 已接入但当前样本未成功
- TUIC

## 运行原理概述

1. 从 ZIP / DB / 分享链接读取节点
2. 将节点转换为统一结构
3. 生成 sing-box 或 Xray 配置并启动本地 SOCKS
4. 通过该 SOCKS 真实请求 `ipify` 获取出口 IP
5. 按任务选择查询 `ip-api + ipapi.is + IPinfo + IP2Location + IPQS + Scamalytics + AbuseIPDB`
6. 合并为统一画像字段
7. 输出 JSON / CSV / Markdown

## 已知说明 / 限制

- 节点“成功”仅代表当前协议映射、sing-box 配置、实际出站链路在本次测试中成立。
- 不同供应商对风险 / 代理 / 机房的判断口径不同，建议结合原始源数据一起看。
- TUIC 当前虽已接入，但你现有 2 条样本未开通，因此没有成功样本。
- 部分节点备注存在历史编码问题，不影响主要测试逻辑，但会影响显示效果。
- 成功节点不等于“家宽精品节点”，当前成功池里仍有不少 datacenter / proxy_or_transit。

## 建议使用流程

- 新协议先小批量验证
- 批量跑完后优先看 `results/csv/` 和 `results/reports/`
- 需要进一步筛节点时，直接看 `success_nodes_shortlist_*.csv`

## 后续可继续完善的方向

- 继续扩大 VMess / Hysteria2 验证范围
- 深挖 TUIC 正式成功样本
- 补充更多协议支持
- 增加更清晰的“精品节点筛选规则”

## FAQ / 注意事项

### 1. 为什么 PowerShell 里看 README / CHANGELOG 会乱码？
通常是终端编码显示问题，不一定是文件本身坏了。优先用 VS Code、Notepad++ 或支持 UTF-8 的编辑器打开。

### 2. 为什么 success 汇总文件会有多个版本？
因为项目前期有过临时生成阶段。现在以最新稳定版为准：
- `success_nodes_full_53_20260320_1438.*`
- `success_nodes_shortlist_34_20260320_1438.*`
旧版本已移动到 `results/reports/archive/`。

### 3. 如何重新生成最新 success 汇总？
```powershell
python scripts/generate_success_reports.py --stamp 20260320_1438
```
如果你想换时间戳，把 `20260320_1438` 改成你自己的即可。

### 4. 成功节点是不是就等于精品节点？
不是。成功只代表当前测试链路跑通。是否值得留用，还要结合 `ip_type_final`、风险分数和原始情报看。
