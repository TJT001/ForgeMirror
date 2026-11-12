# 签名清单 v1（`manifest.sig`）草案

| 项 | 值 |
|---|---|
| 版本 | 0.1（草案） |
| 日期 | 2026-11-12 |
| 状态 | P0 草案；P1 联调后冻结 |
| 关联 | 设计文档 §7.4、§8、§16.6；实施步骤 P0-06 |

## 1. 文件形态

`manifest.sig` 是 UTF-8 JSON 对象。它覆盖加固包内全部受保护产物，但不包含自身，避免自哈希循环。

```json
{
  "schema": "forgemirror.manifest/1",
  "build_id": "00112233-4455-6677-8899-aabbccddeeff",
  "shell_version": "1.0.0",
  "policy_version": 1,
  "rule_version": 1,
  "app": {
    "package": "com.example.app",
    "version_code": 1,
    "cert_sha256": "64-hex"
  },
  "artifacts": [
    {"path": "assets/container.fdx", "size": 1234, "sha256": "64-hex"},
    {"path": "lib/arm64-v8a/libshield_core.so", "size": 5678, "sha256": "64-hex"}
  ],
  "signature": {
    "alg": "ed25519",
    "key_id": "shell-key-2026-11",
    "value": "base64"
  }
}
```

## 2. 规范化与签名

- 使用 **RFC 8785 JSON Canonicalization Scheme（JCS）** 生成待签字节。
- 签名输入：删除顶层 `signature` 成员后的 JCS 字节，UTF-8 编码。
- 算法：Ed25519，64 字节签名，Base64（标准字母表，无换行）。
- 验签公钥由 Bootstrapper 内置，按 `key_id` 选择；轮换时新旧公钥可并存一个发布周期。
- 除 `signature` 外，所有字段都在签名覆盖范围内；未知字段在 v1 中拒绝，避免签名语义漂移。

## 3. 字段约束

| 字段 | 约束 |
|---|---|
| `schema` | 必须为 `forgemirror.manifest/1` |
| `build_id` | UUID 字符串，与此构建容器头部一致 |
| `shell_version` / `policy_version` / `rule_version` | 版本三元组；服务端防降级依据 |
| `app.package` | 与 APK 包名一致 |
| `app.version_code` | 与 APK `versionCode` 一致 |
| `app.cert_sha256` | APK 签名证书 SHA-256，小写十六进制 |
| `artifacts` | 至少 1 项，按 `path` UTF-8 字节序升序 |
| `artifacts[].path` | 相对路径，`/` 分隔；禁止绝对路径、`.`、`..`、反斜杠、空段 |
| `artifacts[].size` | 文件字节数，`>= 0` |
| `artifacts[].sha256` | 文件完整 SHA-256，小写十六进制 |

单清单最多 4096 个产物；单个产物上限按构建 profile 配置，默认 2 GiB。

## 4. 覆盖范围

清单必须包含：

- 全部 DEX 容器与 stub DEX；
- `libshield_boot.so`、`libshield_core.so` 及所有 ABI 变体；
- `policy.pkg`、`rules.pkr`；
- 其他由 S6 注入或改写的 assets。

清单不包含：

- `manifest.sig` 自身；
- APK 签名块（由 APK 签名机制覆盖）。

## 5. 验证顺序

1. 解析 JSON，拒绝重复键、未知字段、类型错误和超限。
2. 重新计算 JCS 字节并验签；失败即进入恢复流程。
3. 逐产物校验路径、大小和 SHA-256；启动关键产物全量校验，其余可抽样。
4. 校验 `app.cert_sha256` 与运行时证书一致。
5. 版本三元组低于已记录值时，交由服务端防降级策略处理。

## 5.1 P1-B 原型信封与算法协商

P1-B 在 `assets/shield/manifest.sig` 中使用信封格式，避免运行时重新做 JSON 规范化：

```json
{
  "alg": "ecdsa-p256-sha256",
  "key_id": "p1b-dev",
  "payload": "base64(canonical manifest JSON)",
  "signature": "base64"
}
```

- `payload` 是 §1 清单对象的规范化字节；签名直接覆盖这段字节。
- 受信公钥以 DER SubjectPublicKeyInfo 放在 `assets/shield/trusted_key.der`。
- `alg` 当前支持 `ecdsa-p256-sha256` 与 `ed25519`。
- **P1-B 默认使用 ECDSA P-256**：Pixel 5 / API 30 的 Java 提供者没有 Ed25519/EdDSA KeyFactory，原型先用系统支持的算法验证链路。
- Ed25519 仍是目标算法；P2 集成原生密码后端后切回，信封和 key_id 不需要改布局。
- 运行时先验签，再解析 `payload`，最后逐产物校验 SHA-256；失败进入恢复流程。

## 6. 待冻结项

- JCS 实现库与跨语言向量；
- 公钥轮换与 `key_id` 命名规则；
- 产物路径规范化的最终字符集；
- 抽样校验的段划分与证据格式。
