# CHANGELOG

## 2026-08-11

- 新增 1Password CLI `op run` 运行时 Key 注入；支持多 Key 环境变量且不会写回本地 DPAPI 配置
- 新增可选的 ipapi.is 注册 Key 配置、轮换与 1Password 注入；未配置时继续使用匿名免费查询
- 设置面板补充 IP-API、ipapi.is、Scamalytics 与 AbuseIPDB 的凭据来源提示

## 2026-08-10

### Web UI 2.3 · Hugging Face 临时云端版
- 新增可部署到 Hugging Face Docker Space 的浏览器开箱即用版本
- 每个标签页使用匿名一小时会话；Key、节点、任务和结果只在单进程内存中临时处理
- 加入手动取消并删除、到期清理、会话隔离、全站并发、节点日配额和临近到期禁开任务
- 云端只允许公网目标，DNS 解析后固定连接地址，阻止私网/回环/元数据访问与 DNS 重绑定
- 上传限制为 4 MB，ZIP 使用请求专属目录并限制文件数、路径、符号链接和解压总量
- 云端每次导入/任务最多 20 节点、并发最多 2、单次网络请求超时最多 12 秒
- Linux 容器自动发现固定版本 sing-box/Xray；镜像校验 SHA256 并附上游许可与源码归档
- 保留完整本地版，并加入可选的 Cloudflare Pages 在线入口跳转构建脚本

### Web UI 2.2 · 公开发布准备
- 新增 Cloudflare Pages 静态在线入口；节点、订阅、Key 和结果只连接本机引擎，不设云端业务 API
- 项目对外名称统一为 Proxy Audit，与 GitHub 仓库名 `proxy-audit` 保持一致
- 项目自有代码采用 Apache License 2.0，并加入 NOTICE 与第三方许可证清单
- 新增简洁中性的负责任使用、隐私、安全政策和公开发布检查清单
- Web UI 增加任务前授权确认；任务 API 同步强制校验并记录说明版本
- 新增本地合规/隐私页面，说明数据保存位置、第三方流向和安全部署边界
- 新增不会回显匹配内容的全 Git 历史敏感信息扫描器与 GitHub Actions 检查
- README 加入仅含合成数据的深色、浅色和授权门槛演示图
- 新增英文 README 和中英文切换入口
- Key 可见性按钮改为标准眼睛图标；设置弹窗底部操作按钮统一尺寸
- 统一 README 中的公开示例路径和验收样本描述

### Web UI 2.1
- IPinfo、IP2Location、IPQS、Scamalytics、AbuseIPDB 支持每个服务商最多 50 个加密 Key
- 多 Key 按请求轮询；遇到 401/402/403/429 或服务商拒绝响应时暂时冷却并自动尝试下一枚
- 设置面板只显示 Key 的脱敏占位或短前缀，支持逐枚移除和整池清空
- 节点预览增加分页、逐项勾选、当前页全选、选择全部筛选结果和清空选择
- 任务 API 支持显式节点 ID 列表，手动选择时只检测所选节点
- 切换历史任务时，顶部节点数和协议统计改为读取该任务自身快照
- 历史任务支持重命名，并将名称持久化到脱敏 raw 记录
- `start-web.cmd` 首次运行自动创建 `.venv`、安装依赖并下载校验固定版本 sing-box
- 浏览器验收新增多 Key 控件、部分选择、历史统计上下文和任务重命名覆盖

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
- 节点解析后立即在结果区显示脱敏预览，并在普通刷新后恢复当前导入
- 从本地脱敏 raw 文件恢复最近任务和结果，默认显示 10 条、支持设置 1–100 条且不删除旧报告
- 页面刷新自动恢复运行中任务或最近结果
- 默认字号增大，并新增深色/浅色/跟随系统与三档字号偏好

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
