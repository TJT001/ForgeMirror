# 规则包 v1（`rules.pkr` / PKR1）

| 项 | 值 |
|---|---|
| 版本 | 0.2（P3 原型） |
| 日期 | 2026-11-13 |
| 状态 | 原型已实现；YARA 引擎与热更新待 P3 后续冻结 |
| 关联 | 设计文档 §4.S4、§7.3、§17.6；实施步骤 P3 |

## 1. 二进制布局

所有整数为 little-endian。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `PKR1` |
| 4 | 2 | `version` | `1` |
| 6 | 2 | `min_shell_version` | `major*10000 + minor*100 + patch` |
| 8 | 1 | `cipher` | `1` = AES-256-GCM |
| 9 | 1 | `sig_alg` | `1` = Ed25519；`2` = ECDSA P-256 raw r‖s |
| 10 | 12 | `nonce` | 随机 |
| 22 | 4 | `plaintext_len` | 规则载荷长度 |
| 26 | `plaintext_len + 16` | `ciphertext` | 密文 + GCM tag |
| 末尾 | 64 | `signature` | 签名（Ed25519 或 ECDSA raw） |

签名覆盖从偏移 0 到 `ciphertext` 结束的全部字节。

## 2. 密码契约

| 项 | 值 |
|---|---|
| 密钥 | `HKDF(K_content, salt=build_id, info="FM/rules/v1")` |
| AEAD | AES-256-GCM |
| AAD | 头部前 26 字节 |
| 签名 | Ed25519 或 ECDSA P-256 raw，公钥与清单一致 |

## 3. 载荷（原型）

载荷是 UTF-8 JSON。`yara` 存在时壳内 YARA 4.5.4 引擎编译并优先使用；否则回退到 all/any 字符串条件。外层信封不变。

```json
{
  "schema": "forgemirror.rules/1",
  "version": 1,
  "min_shell_version": "0.1.0",
  "yara": "rule demo { strings: $a = \"alpha\" condition: $a }",
  "rules": [
    {"id": "demo_all", "logic": "all", "strings": ["alpha", "beta"]},
    {"id": "demo_any", "logic": "any", "strings": ["gamma", "delta"]}
  ]
}
```

约束：

- `rules` 1..256 条；每条 1..32 个非空字符串；
- `logic` 仅支持 `all` / `any`；
- `yara` 可选，UTF-8 源码，上限 64 KiB；编译失败时不加载规则包；
- 解析失败、签名失败或版本不满足时整包拒绝，不部分加载；
- 研究侧九条规则只作研究证据；产品规则独立编写并记录特征来源与许可。

## 4. 运行时

- 壳在 bootstrap 后异步扫描 APK 内 `lib/**/*.so`（上限 64 MB）；
- `yara` 存在时使用壳内 YARA 4.5.4（JNI）扫描，否则按 all/any 字符串匹配；
- 命中写入加密事件队列并批量上报；远端进程不重复上报；
- 扫描不阻塞首帧；规则包纳入清单签名产物，S8 闸门验证签名和密钥绑定。

## 5. 待后续

- 研究侧九条规则的真实语义与产品规则正反例；
- 规则热更新、版本门控与原子替换；
- 内存扫描与 `/proc/self/maps` 候选管理；
- 规则版本与清单 `rule_version` 的一致性。
