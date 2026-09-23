# MoonACME 项目申报书

## 1. 项目名称

MoonACME：面向 MoonBit 的可移植 ACME 证书自动化协议库。

## 2. 项目简介

MoonACME 以 RFC 8555 为依据，在 MoonBit 中实现从 ACME 服务目录、账户、
订单、授权和挑战，到 CSR、签发、下载、吊销与续期的协议核心。项目不绑定
HTTP 客户端、DNS 服务商、Web 框架、系统时钟或私钥存储，native、JavaScript
和 WebAssembly 应用均可复用同一套状态与安全规则。

## 3. 项目方向与通用性

项目属于网络安全与基础协议方向。现有 MoonBit 生态已有 TLS、HTTP、JWS、
JWK 和 X.509 等基础零件，但缺少将这些能力连接成自动证书生命周期的 ACME
客户端。MoonACME 采用“纯协议核心 + 宿主适配器”的结构，可接入不同证书
颁发机构、HTTP 传输、DNS API、Web 服务器、HSM 与密钥库，适合作为其他
MoonBit 服务的基础依赖。

## 4. 预期使用场景

1. MoonBit Web 服务通过 HTTP-01 自动申请证书，并在续期后热加载证书链；
2. 网关、泛域名服务和 SaaS 平台通过 DNS-01 为多个域名集中申请与续期；
3. CI、边缘函数或 Wasm 控制面通过外部签名器管理证书，私钥不进入协议进程；
4. 私有 PKI 使用兼容 RFC 8555 的内部 CA，复用订单、重试和审计状态。

## 5. 拟实现的核心功能

- ACME 目录、订单、授权、挑战与 Problem Details 的强类型严格编解码；
- Flattened JWS、JWK Thumbprint、POST-as-GET 和一次性 Replay-Nonce 管理；
- HTTP-01、DNS-01 计算与通配符规范化，`badNonce` 有界退避；
- PKCS#10 CSR DER 构造与外部签名接口，账户密钥和证书密钥不落入模型；
- 账户注册、下单、挑战确认、finalize、下载、吊销的请求规划；
- 订单/授权状态机、可注入时钟的续期计划、四后端 CI 与命令行辅助工具。

## 6. 原创或移植说明

本项目为原创实现，以 RFC 8555、RFC 7638 和 PKCS#10 标准为行为依据，不移植
现有项目源码。项目复用 MoonBit 生态的 JSON、Base64、SHA-256 与 ASN.1 基础
包，但 ACME 资源模型、nonce 与重试规则、JWS 请求规划、挑战流程、CSR 组装、
状态推导和续期策略均在本仓库实现。

## 7. 查重和差异说明

2026-09-23 使用 Mooncakes 检索 `acme`、`rfc8555`、`letsencrypt`、
`certificate`、`tls`：前三项没有发现 ACME 协议包；后两项仅发现 TLS、X.509
及证书加载等相邻能力。项目不是 Certbot/JS 工具封装，当前 MoonBit 核心约
1,200 行，协议逻辑可独立运行。详细记录见 `docs/DUPLICATION_REVIEW.md`。

## 8. GitHub 仓库

https://github.com/apoloe4/moonacme

仓库采用 Apache-2.0 许可证，现有提交均按资源模型、编解码、挑战、JWS、nonce、
会话、CSR、状态机、CLI、测试与文档拆分为有效提交，数量不少于 10 次。
