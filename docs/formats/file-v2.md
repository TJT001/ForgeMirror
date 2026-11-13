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
3. 写入在内存中修改受影响块；门面整体写入（`writeAll`）若目标已是合法 FMF2，
   先逐块比较，只把差异块标记为脏。持久化时只把**脏块**写入增量 WAL：
   - 新文件/目标缺失：WAL 标记 `full`，包含全部块；
   - 已有目标：WAL 只包含脏块、扩展块和被截断清零的末块；
   - 若整体写入与目标逐块一致，则跳过 WAL 和 fsync；
   - 写 `<name>.fmf2.wal.tmp`（新头部 + 记录 + footer）并 `fsync`；
   - 原子 rename 为 `<name>.fmf2.wal`，`fsync` 目录，作为提交点；
   - 把 WAL 中的新头部和脏块原位写入目标，`setLength` 到新长度，`fsync`；
   - 删除 WAL 并 `fsync` 目录。
4. 打开时先执行恢复（在获取文件锁之后）：
   - WAL 结构、footer SHA-256、新头部 AEAD、每条块 AEAD 全部通过后前滚；
   - 增量 WAL 还要求目标头部 `file_id` 与 WAL 的 `base_file_id` 一致；
   - WAL 损坏、基文件不匹配或块校验失败 → 回滚：删除 WAL，保留原目标；
   - 目标已被前滚但 WAL 未删除 → 重放是幂等的，随后清理 WAL；
   - 无 WAL 时删除遗留 `.wal.tmp` / 旧 `.fmf2.tmp`。
5. 截断时对末块超出新长度的区域清零，防止后续扩展复活旧明文。

### 4.1 WAL `<name>.fmf2.wal`

固定头 128 字节（little-endian），随后是 `record_count` 条记录，最后 52 字节
footer。WAL 不包含业务明文。

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 4 | magic `FMW1` |
| 4 | 2 | version = 1 |
| 6 | 2 | flags（bit0 = full） |
| 8 | 16 | txn id |
| 24 | 16 | base `file_id`（增量 WAL 用） |
| 40 | 72 | 新 FMF2 头部（含 header nonce/tag） |
| 112 | 4 | record count |
| 116 | 4 | record bytes |
| 120 | 8 | reserved |

记录（固定 `chunk_size + 36` 字节）：

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 4 | chunk index |
| 4 | 4 | chunk_len |
| 8 | 12 | chunk nonce |
| 20 | chunk_size | 密文 |
| 20 + chunk_size | 16 | GCM tag |

Footer：`magic FMW1 (4) || txn id (16) || SHA-256(header+records) (32)`。

- `full` WAL 必须包含 `0..chunk_count-1` 全部记录，可在目标缺失时重建；
- 增量 WAL 依赖目标中未记录块仍然有效，因此校验 `base_file_id`；
- 前滚前先完整校验 footer、新头部 tag 和每条记录 tag，避免坏 WAL 写坏目标；
- 旧 `FMJ1` `.fmf2.commit` + `.fmf2.tmp` 恢复路径保留，用于兼容旧版本遗留事务。

### 4.2 崩溃窗口

| 崩溃点 | 恢复行为 |
|---|---|
| WAL tmp 写入中 | 无合法 WAL，删除 tmp，原目标可用 |
| WAL 已 fsync、rename 前 | 删除 tmp，原目标可用（事务未提交） |
| WAL 已 rename、前滚前 | 前滚 WAL |
| 前滚中（目标部分写入） | WAL 仍完整，重放幂等完成 |
| 前滚完成、删除 WAL 前 | 重放幂等，随后清理 WAL |
| 删除 WAL 后 | 事务完成 |

### 4.3 跨进程写合并

可写打开时记录基线：`file_id`、块大小、明文长度和每块 SHA-256。同步时：

- 本地块未改（与基线哈希相同）→ 不写目标，保留其他进程的修改；
- 本地块改动且目标块仍等于基线 → 写本地块；
- 本地块改动且目标块也改动 → 同块冲突，默认 local-wins 并计数；
- 本地未改长度 → 保留目标当前长度；本地改长度 → 本地长度获胜；
- 目标 `file_id`/块大小变化 → 无法对齐基线，退回完整本地写入。

合并结果仍通过增量 WAL 应用；冲突是块级、非字节级，长度冲突也按 local-wins。

### 4.4 限制（事务相关）

- 目录 `fsync` 尽力而为；部分 ROM/文件系统不允许以只读方式打开目录，掉电原子性
  不能对所有设备作绝对保证。
- WAL 只记录脏块，但每条记录仍为固定块大小；随机写会重写整个受影响块。
- 跨进程并发写由文件锁串行化；透明 I/O 与 `openFileOutput` append 已做块级合并，非 append 为截断语义。
- WAL 校验需要两次读取（校验 + 应用）；大文件 fsync 时延需按设备基线评估。

## 5. 迁移

- 读取 `FMF1` 或明文文件时按旧语义整体解密；
- 写模式关闭且内容有变更时，整体写成 `FMF2`；
- 只读模式不迁移。

## 6. 限制

- 未实现 mmap/msync/munmap、直接 syscall；跨进程写已做块级合并，多写者仍由文件锁串行应用；
- 目录 fsync 为尽力而为，未做掉电原子性证明；
- 固定槽位会为末块补零，最大浪费一个块；
- 当前门面限制 64 MiB，格式本身允许更大；
- 增量 WAL 只保存脏块；旧 `FMJ1` 提交日志仅用于兼容恢复。
