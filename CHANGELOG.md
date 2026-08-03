# CHANGELOG

## 2026-03-20

### Added
- 正式接入多源 IP 情报：IPinfo / IP2Location / IPQS / Scamalytics
- 新增统一画像字段：`ip_type_final` / `risk_score_final` / `risk_level_final` / `native_ip_judgement`
- 新增 `enhance_existing_run.py`，支持对已有 raw 结果做二次增强画像
- 新增协议支持：VMess / AnyTLS / Hysteria2 / TUIC（TUIC 已接入但当前样本未成功）
- 新增 `generate_success_reports.py`，用于生成去重后的成功节点总表与 shortlist

### Verified
- VLESS 批量验证成功样本：21
- VMess 首批成功样本：2
- AnyTLS 全量成功样本：6
- Hysteria2 全量成功样本：27
- TUIC 当前样本：2，均未开通，成功样本 0

### Docs
- 新建项目根目录 `README.md`
- 删除旧文档 `scripts/README_run.md`
- 补充使用说明、输出路径、典型命令、当前结果文件说明

### Cleanup
- 新增 `results/reports/archive/`，归档旧的 success 汇总文件
- 保留最新稳定版 success 汇总：`success_nodes_full_53_20260320_1438.*` / `success_nodes_shortlist_34_20260320_1438.*`
- 为 README 补充 FAQ / 注意事项
