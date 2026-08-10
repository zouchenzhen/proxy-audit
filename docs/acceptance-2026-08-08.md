# Proxy Audit 2.0 验收记录（2026-08-08）

本记录只包含去标识化结果，不包含节点名称、服务器、凭据、订阅 URL 或出口 IP。

## 结论

- 代码自动测试：18/18 通过。
- 已安装内核配置校验：11/11“内核 × 协议”组合通过。
- 浏览器 UI：1536×700、1280×720 两个视口通过。
- 使用包含多种受支持协议的授权数据集完成解析、去重和导入验收。
- 本轮获得真实出口：VLESS（sing-box、Xray）、VMess（sing-box、Xray）、Hysteria2（sing-box）、TUIC（sing-box）。
- Trojan、Shadowsocks、AnyTLS 的本轮抽样没有获得在线出口，不能声称真实连通通过；其内核配置语法已通过。

## 环境

- sing-box 1.13.3
- Xray 26.5.9，Windows/amd64
- 去标识化的本地 `guiNDB.db` 验收数据集
- 所有真实检测均通过临时本地 SOCKS 监听出站，结束后删除临时内核配置

数据集覆盖 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC 和 AnyTLS。SOCKS、HTTP、
策略组以及尚未实现的 Shadowsocks 插件传输不会被误计为可检测节点。

## 浏览器 UI 验收

使用隔离的无头 Chrome 和隔离后端真实点击，不接触日常浏览器配置。

| 检查项 | 1536×700 | 1280×720 |
|---|---:|---:|
| 左侧栏横向溢出 | 0 px | 0 px |
| 内核卡片越界 | 无 | 无 |
| 运行区遮挡 | 0 px | 0 px |
| 设置字段溢出 | 0 px | 0 px |
| 设置弹窗锁定背景 | 通过 | 通过 |
| 导入与启动任务 | 通过 | 通过 |
| 结果状态筛选与搜索 | 通过 | 通过 |
| JavaScript 异常 | 0 | 0 |

## 内核与真实网络

配置校验会直接调用已安装内核的 `check`/`-test`，不只是检查 Python 字典。

| 协议 | sing-box 配置 | Xray 配置 | 本轮真实网络 |
|---|---|---|---|
| VLESS | 通过 | 通过 | 双内核成功 |
| VMess | 通过 | 通过 | 双内核成功 |
| Trojan | 通过 | 通过 | 两个内核各抽 3 个，均为节点/上游不可达 |
| Shadowsocks | 通过 | 通过 | 两个内核抽样均未获得出口 |
| Hysteria2 | 通过 | 不适用 | sing-box 成功 |
| TUIC | 通过 | 不适用 | sing-box 成功 |
| AnyTLS | 通过 | 不适用 | 抽 3 个均为节点/上游不可达 |

真实成功样本的质量探测均为 100%（2/2），但样本量很小，不代表长期稳定性。

## 情报源与可选站点端点

使用一个已获得真实出口的授权 VLESS 测试节点逐项调用：

- IP-API、IPinfo、IP2Location、IPQualityScore、Scamalytics、IPAPI.is、AbuseIPDB：均返回数据，provider error 为 0。
- ChatGPT、Claude、GitHub：HTTP 200。
- YouTube：HTTP 204。

站点端点只表示该 HTTP 端点在测试时可达，不表示账号可登录、地区内容已解锁或不会触发风控。

## 尚未证明或明确受限

- 没有穷举整个验收数据集；真实网络部分采用每组少量节点的分散抽样。
- Trojan、Shadowsocks、AnyTLS 没有在本轮得到在线成功样本。
- Shadowsocks 的 v2ray-plugin/obfs 插件传输尚未实现，现会明确跳过。
- SOCKS、HTTP、WireGuard、策略组/链式代理不在当前正式检测范围。
- Xray 不承担 Hysteria2、TUIC、AnyTLS 检测。
- ChatGPT/Claude/GitHub/YouTube 仅做可达性检查，不做完整解锁判定。

## Hysteria2/TUIC uTLS 回归复验

一组授权 Hysteria2/TUIC 测试节点在 `api.ipify.org` 阶段显示
`0x01 General SOCKS server failure`。对应 sing-box 日志的真实根因均为
`unsupported usage for uTLS`：生成器错误地把浏览器指纹作为 uTLS 配置附加给
基于 QUIC 的 Hysteria2/TUIC。

修复后：

- Hysteria2/TUIC 的 TLS 配置不再生成 `utls`；TCP TLS 协议的指纹支持保持不变。
- 修复后的测试节点均成功出站，未再出现 uTLS 错误。
- 自动测试增加到 20 项，包含 Hysteria2/TUIC 指纹回归和错误信息脱敏测试。
- 任务动态显示稳定的中文错误分类；对象内存地址和整段 urllib3/SOCKS 异常不再进入 UI。

## 预览、历史与可读性复验

- 导入完成后、未开始检测前，结果区立即显示脱敏节点列表和“待检测”状态。
- 普通页面刷新后，当前导入预览、运行中任务或当前结果会自动恢复。
- 后端重启后从脱敏 raw 文件恢复最近任务；使用 10 条脱敏任务记录验证，成功恢复 10/10 条，结果行完整。
- 历史显示数量可设为 1–100，默认 10；减少数量不会删除旧 raw/CSV/Markdown 文件。
- 深色、浅色、跟随系统三种模式和标准/较大/特大三档字号均可切换并在刷新后保留。
- 隔离 Chrome 验收覆盖导入预览恢复、任务结果恢复、主题与字号持久化，JavaScript 异常 0。

## 2026-08-10 多 Key、局部检测与历史上下文复验

- 自动测试增加到 26 项，Python 编译、前端 JavaScript 语法与 PowerShell 启动脚本解析均通过。
- 每个限额情报源支持最多 50 个 Key；覆盖旧单 Key 配置迁移、去重、逐枚移除、安全短前缀、鉴权失败或限额后的自动轮换。
- 公共设置 API 只返回 Key 数量、不可逆标识和短前缀，不返回完整 Key。
- 导入 2 个隔离测试节点后，手动只勾选 1 个；后端任务实际总数为 1，证明不是只做前端视觉筛选。
- 搜索、协议等筛选可以和“选择当前筛选结果”组合，未选择时仍保持全量检测的原有行为。
- 切换到历史任务后，顶部节点数、协议摘要、进度与结果都取自历史快照，不再沿用当前导入数量。
- 历史任务重命名经 Web API 写入脱敏 raw 记录，重启恢复后名称仍保留。
- 1536×900 隔离 Chrome 验收：设置字段溢出 0、左栏横向溢出 0、运行区遮挡 0、JavaScript 异常 0。
- UI 自动化覆盖设置、多 Key 控件、导入预览、局部选择、任务恢复、历史上下文、历史重命名、筛选、主题与字号持久化。
- 从当前提交新建不含 `.venv`、本地配置或内核二进制的干净 clone，双击脚本等价流程成功自动建环境、装依赖、下载内核并启动 2.1.0；sing-box 1.13.3 可用，发行压缩包 SHA256 与脚本固定值一致。

## 2026-08-10 公开发布合规复验

- 自动测试增加到 29 项；新增后端授权门槛、`/legal` 页面和历史扫描器自身的检测/不回显测试。
- 未提交 `authorization_confirmed: true` 时，任务管理器和 Web API 均拒绝启动；UI 每次导入和每次任务后重置确认状态。
- 全部可达 Git 提交、历史 blob、当前受版本控制文件和未忽略工作区文件完成敏感模式扫描，未发现真实订阅 URL、代理分享链接、UUID、密码、API Token 或曾被跟踪的本机配置/结果路径。
- 隔离 Chrome 复验覆盖授权门槛与本地合规页：1536×900 无横向溢出，JavaScript 异常 0。
- 四张公开演示图只使用 `.invalid` 假节点；PNG 元数据为空，不含本机路径、订阅、出口 IP 或完整 Key。
- Apache-2.0 正文与 Apache Software Foundation 官方文本逐字符核对一致；sing-box、Xray-core 与 Python 依赖单列第三方许可，不随仓库重新许可。
