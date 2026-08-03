# proxy_audit

Windows 11 下的代理节点批量检测工具。目标是从 v2rayN 备份 / 数据库 / 分享链接中读取节点，使用 sing-box 建立本地代理并真实出站测试，查询出口 IP 的多源情报，最后输出可读报表。

## 当前能力

已有真实成功样本的协议：
- VLESS
- VMess
- AnyTLS
- Hysteria2

已接入但当前样本未成功：
- TUIC

已接入的 IP 情报源：
- ipify
- ip-api
- IPinfo
- IP2Location
- IPQualityScore (IPQS)
- Scamalytics

统一输出字段包括：
- `ip_type_final`
- `risk_score_final`
- `risk_level_final`
- `native_ip_judgement`

## 目录结构

```text
proxy_audit/
├─ bin/
│  └─ sing-box.exe
├─ scripts/
│  ├─ proxy_audit_batch.py
│  ├─ enhance_existing_run.py
│  ├─ generate_success_reports.py
│  ├─ lib_v2rayn.py
│  ├─ lib_singbox.py
│  ├─ lib_ipintel.py
│  └─ lib_report.py
├─ config.local.json
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
- `E:/Openclaw_Workspace/proxy_audit/bin/sing-box.exe`
- 可访问外网
- `config.local.json` 中填写好多源情报 API key

推荐先进入项目目录：

```powershell
cd E:/Openclaw_Workspace/proxy_audit
```

## 配置文件

### `config.local.json`

示例：

```json
{
  "ip2location_api_key": "...",
  "ipinfo_api_key": "...",
  "ipqs_api_key": "...",
  "scamalytics_user": "...",
  "scamalytics_api_key": "..."
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
3. 生成 sing-box 配置并启动本地 SOCKS
4. 通过该 SOCKS 真实请求 `ipify` 获取出口 IP
5. 查询 `ip-api + IPinfo + IP2Location + IPQS + Scamalytics`
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
