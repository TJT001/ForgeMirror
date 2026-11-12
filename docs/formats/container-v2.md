# 容器 v2（FDX2）格式规格（草案）

| 项 | 值 |
|---|---|
| 版本 | 0.1（草案） |
| 日期 | 2026-11-12 |
| 状态 | P0 草案；P1 双端联调后冻结，冻结前可修订 |
| 关联 | 设计文档 §7.1、§16.3；实施步骤 P0-05、P1-A3 |
| 构建侧实现 | `backend/pipeline/forgemirror/formats/container.py` |
| 向量 | `backend/tests/vectors/container/v2/` |

本规格是 Python 构建侧与 C++ 运行时读取侧的格式依据。P0 先验证最小双端编解码；P1 联调后冻结字段、偏移、限额和测试向量。冻结后任何布局变更必须提升版本号并重新生成向量。

## 1. 约定

- 所有整数字段为 **little-endian**；唯一例外是块 nonce 中的块序号，为 **big-endian**。
- 所有偏移从容器文件起始位置计算。
- 长度字段为无符号整数；读取方必须拒绝越界、溢出、重叠和未知关键标志。
- 容器自身不携带签名；完整性由 `manifest.sig` 覆盖整个容器文件的 SHA-256，以及 TOC 的 GCM tag 双重保证。
- 容器内不保存文件名；文件顺序由 TOC 下标决定，文件名映射记录在构建产物 `dex_manifest.json`。

## 2. 密码契约

| 项 | 值 |
|---|---|
| 内容密钥 `K_content` | 32 字节，每构建随机生成，服务端 HSM 授权分发 |
| KDF | HKDF-SHA-256 |
| HKDF salt | `build_id`（16 字节） |
| 块密钥 | `HKDF(K_content, salt=build_id, info="FM/fdx2/chunk/v1")`，32 字节 |
| TOC 密钥 | `HKDF(K_content, salt=build_id, info="FM/fdx2/toc/v1")`，32 字节 |
| AEAD | AES-256-GCM，tag 16 字节 |
| 块大小 | 65536 字节（最后一块可短） |
| 块 nonce | `nonce_prefix(8) || BE32(global_chunk_index)`，共 12 字节 |
| TOC nonce | 12 字节随机，存于头部 |
| 块 AAD | 40 字节，见 §5 |
| TOC AAD | 128 字节完整头部 |

`global_chunk_index` 跨全部文件连续递增，从 0 开始，不得回绕。`nonce_prefix` 每构建随机生成；重新构建必须使用新的 `K_content` 与 `nonce_prefix`。`file_id` 只作标识，不承担 nonce 唯一性。

## 3. 头部（128 字节）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `FDX2` |
| 4 | 2 | `version` | `2` |
| 6 | 2 | `header_size` | `128` |
| 8 | 4 | `flags` | 必须为 `0`；非零拒绝 |
| 12 | 1 | `alg` | `1` = AES-256-GCM |
| 13 | 1 | `kdf` | `1` = HKDF-SHA-256 |
| 14 | 2 | `reserved` | `0` |
| 16 | 16 | `build_id` | 构建 UUID 原始字节 |
| 32 | 4 | `file_count` | `1..64` |
| 36 | 4 | `chunk_size` | 必须为 `65536` |
| 40 | 8 | `nonce_prefix` | 随机字节 |
| 48 | 12 | `toc_nonce` | 随机字节 |
| 60 | 4 | `reserved2` | `0` |
| 64 | 8 | `total_plaintext_size` | 所有文件明文总长 |
| 72 | 4 | `total_chunk_count` | 全局块数，`<= 32768` |
| 76 | 4 | `reserved3` | `0` |
| 80 | 8 | `toc_offset` | TOC 密文起始偏移 |
| 88 | 8 | `toc_size` | TOC 密文长度（含 16 字节 tag） |
| 96 | 32 | `reserved4` | `0` |

头部整体作为 TOC 的 AAD。头部任意字节被篡改都会导致 TOC 解密失败。

## 4. TOC 明文

TOC 明文为 `file_count` 个连续的 72 字节条目，按文件顺序排列，无额外头尾。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `file_index` | 从 0 开始，必须等于条目位置 |
| 4 | 4 | `flags` | 必须为 `0` |
| 8 | 8 | `file_id` | `LE64(SHA-256(orig)[0:8])`，仅作标识 |
| 16 | 8 | `plaintext_size` | 原始文件长度 |
| 24 | 4 | `chunk_size` | 必须为 `65536` |
| 28 | 4 | `chunk_count` | `ceil(plaintext_size / chunk_size)` |
| 32 | 8 | `data_offset` | 该文件首块密文偏移 |
| 40 | 32 | `plaintext_sha256` | 原始文件完整 SHA-256 |

TOC 密文长度 `toc_size` 必须等于 `16 + 72 * file_count`。文件数据区必须从 `header_size` 开始连续排列，无空洞、无重叠；最后一个文件数据结束处必须等于 `toc_offset`。TOC 密文结束处必须等于容器文件长度，禁止尾部填充。

## 5. 块 AAD（40 字节）

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 4 | `magic` = `FDX2` |
| 4 | 2 | `version` = `2` |
| 6 | 1 | `alg` = `1` |
| 7 | 1 | `kdf` = `1` |
| 8 | 16 | `build_id` |
| 24 | 4 | `file_index` |
| 28 | 4 | `global_chunk_index` |
| 32 | 4 | `plaintext_len`（本块明文长度） |
| 36 | 4 | `flags` = `0` |

## 6. 布局

```
+----------------------+ 0
| header (128)         |
+----------------------+ 128
| file 0 chunk 0..n    |  每块 ciphertext = plaintext + 16B tag
| file 1 chunk 0..n    |
| ...                  |
+----------------------+ toc_offset
| TOC ciphertext + tag |
+----------------------+ toc_offset + toc_size == file size
```

## 7. 读取方校验顺序

1. 文件长度 `>= 128`；头部 `magic/version/header_size/alg/kdf/flags/reserved` 全部合法。
2. `file_count`、`chunk_size`、`total_chunk_count` 在限额内；`toc_offset >= 128`。
3. `toc_size == 16 + 72 * file_count`；`toc_offset + toc_size == file_size`。
4. 用 TOC 密钥与头部 AAD 解密 TOC；tag 失败即拒绝。
5. 逐条目校验下标、标志、长度、块数、偏移连续性与总长一致性；任何一项不满足即拒绝，不进入块解密。
6. 逐块解密并校验 SHA-256；任一块 tag 失败或哈希不符即拒绝，不返回部分结果。

读取方不得依据头部字段预分配无界内存；单文件上限 1 GiB，单容器上限 2 GiB。

## 8. 负例要求

测试必须覆盖并拒绝：

- 头部/块/TOC 任意位置单字节篡改；
- 截断容器、尾部追加数据；
- 错误 tag、错误 AAD 字段、错误 `build_id`；
- 未知 `flags`、未知 `alg/kdf`、非法 `chunk_size`；
- 文件条目重排、下标不连续、偏移重叠或空洞；
- 重复 nonce（复制他块密文到当前块）；
- 超大长度、块数溢出、`toc_size` 不匹配。

## 9. 测试向量

`backend/tests/vectors/container/v2/` 下每个用例包含：

- `container.fdx`：容器本体；
- `meta.json`：`k_content`、`build_id`、`nonce_prefix`、`toc_nonce`、文件列表与 SHA-256。

向量使用公开测试密钥，仅用于格式验证，禁止用于生产。生成命令：

```bash
python3 backend/pipeline/scripts/gen_container_vectors.py
```

## 10. 冻结清单

P1 冻结前必须确认：

- C++ 读取器对同一组向量输出与 Python 一致；
- 头部/TOC/AAD 的端序、宽度、偏移和限额不再变动；
- 负例全部被拒绝；
- `manifest.sig` 覆盖完整容器哈希；
- 版本号、向量和生成脚本一并入库。
