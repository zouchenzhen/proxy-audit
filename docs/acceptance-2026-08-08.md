# Proxy Audit 2.0 验收记录（2026-08-08）

本记录只包含去标识化结果，不包含节点名称、服务器、凭据、订阅 URL 或出口 IP。

## 结论

- 代码自动测试：18/18 通过。
- 已安装内核配置校验：11/11“内核 × 协议”组合通过。
- 浏览器 UI：1536×700、1280×720 两个视口通过。
- 当前 v2rayN 数据库：原始 2002 条；Web API 去重导入 1145 条。
- 本轮获得真实出口：VLESS（sing-box、Xray）、VMess（sing-box、Xray）、Hysteria2（sing-box）、TUIC（sing-box）。
- Trojan、Shadowsocks、AnyTLS 的本轮抽样没有获得在线出口，不能声称真实连通通过；其内核配置语法已通过。

## 环境

- sing-box 1.13.3
- Xray 26.5.9，Windows/amd64
- 本机当前 `guiNDB.db`，共 2002 条记录
- 所有真实检测均通过临时本地 SOCKS 监听出站，结束后删除临时内核配置

按当前项目实现可检测的数据库记录：

| 内核 | 可检测数 | 协议分布 |
|---|---:|---|
| sing-box | 1976 | VLESS 1362、VMess 82、Trojan 286、SS 66、Hysteria2 171、TUIC 3、AnyTLS 6 |
| Xray | 1796 | VLESS 1362、VMess 82、Trojan 286、SS 66 |

其余记录属于 SOCKS/HTTP/策略组，或使用当前尚未实现的 Shadowsocks 插件传输。

## 浏览器 UI 验收

使用隔离的无头 Chrome 和隔离后端真实点击，不接触用户主浏览器配置。

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

配置校验会直接调用本机内核的 `check`/`-test`，不只是检查 Python 字典。

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

使用一个已获得真实出口的 VLESS 节点逐项调用：

- IP-API、IPinfo、IP2Location、IPQualityScore、Scamalytics、IPAPI.is、AbuseIPDB：均返回数据，provider error 为 0。
- ChatGPT、Claude、GitHub：HTTP 200。
- YouTube：HTTP 204。

站点端点只表示该 HTTP 端点在测试时可达，不表示账号可登录、地区内容已解锁或不会触发风控。

## 尚未证明或明确受限

- 没有穷举 2002 个节点；真实网络部分是每组最多 3 个的分散抽样。
- Trojan、Shadowsocks、AnyTLS 没有在本轮得到在线成功样本。
- Shadowsocks 的 v2ray-plugin/obfs 插件传输尚未实现，现会明确跳过。
- SOCKS、HTTP、WireGuard、策略组/链式代理不在当前正式检测范围。
- Xray 不承担 Hysteria2、TUIC、AnyTLS 检测。
- ChatGPT/Claude/GitHub/YouTube 仅做可达性检查，不做完整解锁判定。

## 17:02 用户运行问题复验

用户实际运行中 4 个 Hysteria2/TUIC 节点在 `api.ipify.org` 阶段显示
`0x01 General SOCKS server failure`。对应 sing-box 日志的真实根因均为
`unsupported usage for uTLS`：生成器错误地把浏览器指纹作为 uTLS 配置附加给
基于 QUIC 的 Hysteria2/TUIC。

修复后：

- Hysteria2/TUIC 的 TLS 配置不再生成 `utls`；TCP TLS 协议的指纹支持保持不变。
- 截图中的 4 个同名节点逐个真实复测，4/4 成功出站，uTLS 错误 0。
- 自动测试增加到 20 项，包含 Hysteria2/TUIC 指纹回归和错误信息脱敏测试。
- 任务动态显示稳定的中文错误分类；对象内存地址和整段 urllib3/SOCKS 异常不再进入 UI。

## 预览、历史与可读性复验

- 导入完成后、未开始检测前，结果区立即显示脱敏节点列表和“待检测”状态。
- 普通页面刷新后，当前导入预览、运行中任务或当前结果会自动恢复。
- 后端重启后从脱敏 raw 文件恢复最近任务；本机现有记录按默认值成功恢复 10/10 条，结果行完整。
- 历史显示数量可设为 1–100，默认 10；减少数量不会删除旧 raw/CSV/Markdown 文件。
- 深色、浅色、跟随系统三种模式和标准/较大/特大三档字号均可切换并在刷新后保留。
- 隔离 Chrome 验收覆盖导入预览恢复、任务结果恢复、主题与字号持久化，JavaScript 异常 0。
