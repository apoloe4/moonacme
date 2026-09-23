# 选题查重记录

检索日期：2026-09-23。检索范围为 Mooncakes 包索引、GitHub 公开仓库和本地
依赖源码。使用了以下查询：

```text
moon search acme --limit 20
moon search rfc8555 --limit 20
moon search letsencrypt --limit 20
moon search certificate --limit 20
moon search tls --limit 20
GitHub: MoonBit ACME RFC8555
```

## 结果

- `acme` 只命中 `gmlewis/fonts-a/acme_regular` 字体，和证书协议无关。
- `rfc8555`、`letsencrypt` 没有命中 MoonBit 包。
- `certificate`、`tls` 命中的项目属于相邻层：`moonbitstack/mooncred`
  处理 JWK/JWS/X.509，`moonbitstack/moontls` 和 `moonbitlang/async/tls`
  处理 TLS，`moonbitstack/mooncat` 能加载证书，均不实现 ACME 账户、订单、
  授权、挑战、重放 nonce、`badNonce` 重试和续期流程。
- GitHub 检索能找到 Go、Node.js 等语言的 ACME 客户端，没有发现以 MoonBit
  为实现语言的 RFC 8555 客户端库。

因此 MoonACME 与现有包是组合关系：它调用 JSON、编码、哈希和 ASN.1 基础
能力，为 Web 服务器和 TLS 栈补上自动申请与续期这一层，没有复制通用密码学、
HTTP 客户端或 TLS 实现。

## 与通用脚本封装的区别

MoonACME 的核心为 12 个 MoonBit 源文件、约 1,200 行协议实现，并非调用
Certbot 的进程封装。实现内容包括强类型资源模型、严格编解码、确定性 JWS、
一次性 nonce 池、有限重试策略、挑战计算、PKCS#10 DER 组装、订单状态推导和
续期计划。外部 HTTP 与签名器只负责执行效果，使相同核心能在 native、JS、
Wasm 和 wasm-gc 上复用。

## 后续复核

提交前和每个季度发布前重复以上查询。如出现同类包，将从协议覆盖、目标后端、
安全边界、可插拔传输和互操作测试五方面重新比较，并在 README 中更新差异。
