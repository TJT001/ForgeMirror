# 加密文件 v2（`FMF2`）草案

| 项 | 值 |
|---|---|
| 版本 | 0.1（草案） |
| 日期 | 2026-11-13 |
| 状态 | P3 原型；与 FMF1 并存，写入时迁移 |
| 关联 | 设计文档 §16.4、§17.5；实施步骤 P3-1、FILE-05/07 |

## 1. 目标

- 支持按块随机读写，不必解密整个文件；
- 每次重写同一块使用新的 nonce，避免 GCM nonce 重用；
- 原子迁移与崩溃恢复：原文件在临时文件完成并 fsync 后才替换；
- 截断后重新扩展不得复活已截断的明文。

## 2. 二进制布局

所有整数为 little-endian。固定块大小（默认 65536 字节），每块占固定槽位，便于 O(1) 定位。

### 2.1 头部（72 字节）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `FMF2` |
| 4 | 2 | `version` | `2` |
| 6 | 1 | `algorithm` | `1` = AES-256-GCM |
| 7 | 1 | `flags` | `0` |
| 8 | 16 | `file_id` | 随机，文件身份 |
| 24 | 4 | `chunk_size` | 默认 65536 |
| 28 | 8 | `plaintext_len` | 逻辑明文长度 |
| 36 | 4 | `chunk_count` | `ceil(plaintext_len / chunk_size)` |
| 40 | 12 | `header_nonce` | 随机 |
| 52 | 16 | `header_tag` | GCM tag |
| 68 | 4 | `reserved` | `0` |

`header_tag = AES-GCM(key, header_nonce, plaintext="", AAD=header[0..52])`，
tag 覆盖 `file_id`、块大小、明文长度与块数量。

### 2.2 块记录

从偏移 72 开始，每块固定 `chunk_size + 28` 字节：

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 12 | `chunk_nonce` |
| 12 | `chunk_size` | 密文 |
| 12 + `chunk_size` | 16 | GCM tag |

第 `i` 块逻辑明文长度：

```text
chunk_len = min(chunk_size, plaintext_len - i * chunk_size)
```

末块不足 `chunk_size` 时补零后加密；读取时只返回 `chunk_len` 字节。

## 3. 密码契约

| 项 | 值 |
|---|---|
| 密钥 | 文件域密钥（`HKDF(K_content, build_id, "FM/files/v1")`） |
| AEAD | AES-256-GCM，128-bit tag |
| 块 nonce | 每次写入该块时重新随机生成并存入记录 |
| 块 AAD | `magic(4) \|\| version(2) \|\| file_id(16) \|\| chunk_index(4) \|\| chunk_len(4)` |
| 头部 nonce | 每次持久化重新随机生成 |
| 头部 AAD | `header[0..52]` |

块 AAD 不包含全文件长度，因此扩展/截断只重写受影响的末块，不要求重写全部分块。
文件长度由头部 tag 认证。

## 4. 写入与恢复

1. 打开 `FMF2` 时校验头部长度、magic、版本、算法、块大小、`chunk_count`、
   文件总长与 `header_tag`；任何不一致拒绝。
2. 读取某块时校验该块 tag；失败拒绝，不返回部分明文。
3. 写入在内存中修改受影响块，持久化时：
   - 在同目录创建 `<name>.fmf2.tmp`；
   - 写新头部（新 nonce/tag）；
   - 顺序复制未修改块（原始密文），重写脏块（新 nonce）；
   - `fsync` 后原子 rename 覆盖目标；
   - 失败删除临时文件，原文件保持可用。
4. 打开时删除遗留的 `.fmf2.tmp`（不支持多进程并发写）。
5. 截断时对末块超出新长度的区域清零，防止后续扩展复活旧明文。

## 5. 迁移

- 读取 `FMF1` 或明文文件时按旧语义整体解密；
- 写模式关闭且内容有变更时，整体写成 `FMF2`；
- 只读模式不迁移。

## 6. 限制

- 未实现 mmap/msync/munmap、文件锁、直接 syscall 与并发写；
- 未实现目录 fsync 与掉电原子性证明；
- 固定槽位会为末块补零，最大浪费一个块；
- 当前门面限制 64 MiB，格式本身允许更大。
