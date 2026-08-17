---
title: Proxy Audit
emoji: 🔎
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
short_description: 临时会话的节点连通性与出口 IP 质量检测面板
---

# Proxy Audit

节点连通性与出口 IP 质量检测面板。请仅检测本人所有、本人管理或已经取得明确授权的
节点，并遵守所在地法律法规和第三方服务条款。

在线版会把节点、订阅、API Key 和结果上传到本 Space 的临时后端。匿名会话最长一小时，
到期或手动删除会触发取消与清理；活动请求可能在最长 12 秒超时后释放。完成后请立即
导出结果。高敏感、大批量或需要持久历史的场景请使用
[GitHub 仓库](https://github.com/zouchenzhen/proxy-audit)中的本地版。

Proxy Audit 不为在线版建立用户数据库、结果历史或开发者遥测接口，也不嵌入第三方分析
SDK。会话令牌只保存在当前浏览器标签页的 `sessionStorage`。Hugging Face 仍会处理托管
服务所需的常规访问元数据；订阅服务器、IP 情报商和测试端点会收到完成所选请求所必需的
数据。具体边界以页面首次打开时的隐私提示为准。

镜像内固定分发的第三方许可与对应版本源码归档可从运行中的 Space 获取：

- `/third-party/licenses/sing-box-LICENSE`
- `/third-party/source/sing-box-1.13.3-source.tar.gz`
- `/third-party/licenses/xray-LICENSE`
- `/third-party/source/xray-26.3.27-source.tar.gz`
