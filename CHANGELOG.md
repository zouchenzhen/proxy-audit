# CHANGELOG

## 2026-08-08

### Web UI 2.0
- 新增本地 Web 控制台：节点导入、任务进度、结果筛选、详情与安全导出
- 新增 sing-box / Xray 双检测内核及可用性发现
- 新增订阅 URL、Base64 正文、TXT、ZIP、SQLite 导入
- 分享链接解析扩展到 VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / AnyTLS
- 新增并发检测、取消任务、延迟/抖动采样和可选服务端点探测
- 新增 ipapi.is 与 AbuseIPDB，所有情报源可按任务开关
- Key 改为 Windows DPAPI 加密保存，Web API 仅返回配置状态
- 新任务持久化和导出统一剔除节点 UUID、密码、订阅地址与日志尾部
- 项目路径改为相对定位，可移动到其他目录运行
- 新增解析器、内核配置与 Web API 自动测试

### 2.0 验收修正
- 修复 125% 缩放/低高度视口下内核卡片越过侧栏、运行按钮遮挡配置项的问题
- 设置弹窗锁定背景滚动，并将无标签复选框改为明确的“清除”控件
- 新增隔离 Chrome 浏览器验收，覆盖布局、设置、导入、任务、导出启用与结果筛选
- 按当前 v2rayN 枚举修正 Shadowsocks/SOCKS 类型，并适配 Password、Username、ProtoExtra、TransportExtra
- 修复 TUIC ALPN 层级、AnyTLS 默认 TLS，以及新版 Xray 已移除的 allowInsecure 字段
- 明确拒绝尚未实现的 Shadowsocks 插件传输，避免把无效配置误算为可检测节点
- 新增隐私安全的本地真实网络验收脚本和验收报告
- 修复 Hysteria2/TUIC 被错误附加 uTLS 指纹而在出站时报 `unsupported usage for uTLS`
- 任务动态改用稳定的中文错误分类，不再显示含对象地址的底层 SOCKS/Python 异常串

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
