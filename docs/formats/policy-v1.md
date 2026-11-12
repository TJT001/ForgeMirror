# 策略包 v1（`policy.pkg` / SPK1）草案

| 项 | 值 |
|---|---|
| 版本 | 0.1（草案） |
| 日期 | 2026-11-12 |
| 状态 | P0 草案；P1 联调后冻结 |
| 关联 | 设计文档 §4.S3、§7.2、§16.4、§17.5；实施步骤 P0-06、P1-D |

## 1. 二进制布局

所有整数为 little-endian。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `SPK1` |
| 4 | 2 | `version` | `1` |
| 6 | 1 | `cipher` | `1` = AES-256-GCM |
| 7 | 1 | `reserved` | `0` |
| 8 | 12 | `nonce` | 随机 |
| 20 | 4 | `plaintext_len` | 明文 JSON 长度 |
| 24 | `plaintext_len + 16` | `ciphertext` | 密文 + GCM tag |
| 末尾 | 64 | `signature` | Ed25519 |

签名覆盖从偏移 0 到 `ciphertext` 结束的全部字节。`signature` 不参与签名。

## 2. 密码契约

| 项 | 值 |
|---|---|
| 密钥 | `HKDF(K_content, salt=build_id, info="FM/policy/v1")`，32 字节 |
| AEAD | AES-256-GCM |
| nonce | 12 字节随机，存于头部 |
| AAD | 头部前 24 字节（`magic` 到 `plaintext_len`） |
| 签名 | Ed25519，公钥与清单一致 |

## 3. 明文 JSON

```json
{
  "schema": "forgemirror.policy/1",
  "version": 1,
  "min_shell_version": "1.0.0",
  "rules": [
    {"pattern": "shared_prefs/*.xml", "action": "encrypt"},
    {"pattern": "files/**/*.dat", "action": "encrypt"}
  ],
  "excludes": [
    {"pattern": "databases/*.db"},
    {"pattern": "cache/**"}
  ]
}
```

### 3.1 匹配语义

- 路径相对于应用数据目录，使用 `/` 分隔，不以 `/` 开头。
- `*` 匹配单个路径段内的任意字符（不含 `/`）。
- `**` 匹配零个或多个路径段。
- `?` 匹配单个字符（不含 `/`）。
- 排除项优先于规则项；命中排除项即保持明文。
- 规则按声明顺序匹配，首个命中生效；无命中默认不加密。
- 符号链接、`..` 和绝对路径在匹配前拒绝。

### 3.2 字段约束

| 字段 | 约束 |
|---|---|
| `schema` | 必须为 `forgemirror.policy/1` |
| `version` | 正整数，单调递增 |
| `min_shell_version` | 语义化版本；低于该版本的壳拒绝加载 |
| `rules` / `excludes` | 最多 1024 项；pattern 长度 1..512 |
| `action` | v1 仅支持 `encrypt` |

## 4. 验证顺序

1. 校验长度、`magic`、`version`、`cipher`、`reserved` 和 `plaintext_len` 上限。
2. 用 manifest/Bootstrapper 公钥验签；失败拒绝。
3. 用策略密钥与 AAD 解密；tag 失败拒绝。
4. 解析 JSON，拒绝未知字段、重复键和超限。
5. 校验 `min_shell_version` 与当前壳版本。
6. 解析规则并构建匹配器；任何非法 pattern 使整包拒绝，不部分生效。

## 5. 更新与回滚

- 新策略包必须版本号更高，旧版本拒绝。
- 更新采用临时文件 + fsync + 原子 rename；失败保留已验证版本。
- 策略包不包含生产密钥；测试密钥仅用于向量。

## 6. 待冻结项

- pattern 语法的最终字符集与转义规则；
- 与 FILE-02 的匹配器实现对齐；
- 策略版本与 `policy_version` 在清单中的一致性校验；
- 跨进程读取与缓存失效策略。
