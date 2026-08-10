# 公开发布检查清单

仓库改为 Public 前逐项确认：

- [ ] `LICENSE` 为完整、未修改语义的 Apache License 2.0 文本；
- [ ] `NOTICE`、`THIRD_PARTY_NOTICES.md`、`TRADEMARKS.md`、`COMPLIANCE.md`、`PRIVACY.md`、`SECURITY.md` 已更新；
- [ ] `git status --short` 为空，且本机配置、内核、输入、结果和临时目录均被忽略；
- [ ] `python scripts/scan_git_history.py` 对所有可达提交和 blob 返回 0；
- [ ] 单元/API/安全测试与隔离浏览器 UI 验收通过；
- [ ] README 和演示图不含真实订阅、节点名、域名、出口 IP、用户名、路径、Key 或 Key 前缀；
- [ ] GitHub 私密漏洞报告（Private vulnerability reporting）已启用；
- [ ] 分支保护要求测试工作流通过；
- [ ] 仓库 About、Topics 和 Release 描述不使用“翻墙”“解锁保证”“匿名保证”等误导宣传；
- [ ] 未随仓库或 Release 打包 sing-box、Xray 或其他第三方二进制；如需分发，已另做许可证审查；
- [ ] 没有运行公共 SaaS、收费检测、节点推广或公网面板；如未来改变，已完成独立法律与安全评估；
- [ ] 已确认所有提交作者有权按 Apache-2.0 提交其贡献。

建议公开后立即检查 GitHub 的 Secret scanning / Push protection 提示，并再次查看仓库文件、
历史提交和 Actions 日志。若扫描发现真实凭据：先撤销/轮换凭据，再决定是否在取得协作者
同意后重写 Git 历史；只删除当前分支文件不能使旧提交中的秘密失效。
