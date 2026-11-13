# 2026-11-13 P1：FMF2 增量 WAL 与崩溃恢复

## 范围

把 `ShieldChunkStore`（FMF2）的持久化从“完整临时镜像 + 提交记录”改为
**只记录脏块的增量 WAL**，并在打开时前滚/回滚；旧 `FMJ1` 提交记录保留用于兼容。

## 实现

| 位置 | 内容 |
|---|---|
| `ShieldChunkStore.persist` | 只把脏块写入 `.fmf2.wal.tmp` → fsync → 原子改名为 `.fmf2.wal` → 目录 fsync → 原位应用 → 删除 WAL |
| `ShieldChunkStore.recover` | 获取文件锁后、读取目标前执行；先处理旧 `.fmf2.commit`，再处理 WAL |
| `applyWalFile` | 校验 footer SHA-256、新头部 AEAD、每条块 AEAD；增量 WAL 再校验 `base_file_id`；校验通过后写头部/块并 `setLength` |
| `prepareWal` / `prepareWalPatch` | 测试用 WAL 生成入口（完整镜像 / 单块增量） |
| `writeAll` | 已有合法目标先逐块比较，只把差异块标记 dirty，再由 WAL 记录；无差异时跳过 WAL/fsync；目标损坏/缺失才走 full WAL |
| `ShieldFiles.ShieldFileOutputStream` | 改为 FMF2 + `writeAll`/`writeMerged`；`close()` 幂等，append 接入跨进程合并 |

## WAL 格式（`FMW1`）

```text
header 128B: magic|version|flags|txn|base_file_id|new_header(72)|
             record_count|record_bytes|reserved
record:      index(4)|chunk_len(4)|nonce(12)|ciphertext(chunk_size)|
             tag(16) = chunk_size + 36
footer 52B:  magic|txn|SHA-256(header+records)
```

- `flags.bit0 = full`：新文件/目标缺失时包含全部块，可独立重建；
- 增量 WAL 只包含脏块、扩展块和截断清零的末块；
- 目标未记录块仍来自旧 FMF2，故增量恢复要求目标头部 `file_id` 与
  `base_file_id` 一致；
- 应用前先完整校验，坏 WAL 不会写坏目标。

## 崩溃窗口

```text
WAL tmp 写入中          -> 删除 tmp，原目标可用
WAL fsync 后 rename 前  -> 事务未提交，删除 tmp
WAL 已提交、前滚前      -> 前滚
前滚中                  -> WAL 完整，重放幂等
前滚完成、删除 WAL 前    -> 重放幂等，随后清理
WAL 删除后              -> 完成
```

目录 fsync 尽力而为：部分 ROM/文件系统不允许只读打开目录。

## 测试

`ShieldChunkStoreTest` 26 项通过（含跨进程合并 3 项），新增：

- `incrementalWalOnlyLogsDirtyChunks`：修改首块，WAL 明显小于完整文件；
- `writeAllUpdatesExistingChunksThroughWal`：生产 `writeAll` 对已有目标走差异块 WAL；
- `fullWalReplayCreatesMissingTarget`：目标缺失时由 full WAL 重建；
- `corruptedWalRollsBack`：WAL 截断后保留原目标；
- `appliedWalLeftoverIsIdempotent`：前滚后残留 WAL 重放幂等并清理；
- `committedJournalReplaysPreparedImage` 等旧 `FMJ1` 兼容用例继续通过；
- 既有截断、stale tmp、并发锁、重命名、nonce 轮换用例继续通过。

Shield JVM 总计 39 项。

设备回归（demo，Pixel 5 / API 30）：

```text
readback prefs=true counter=1 file=true append=true ra=true
         mmap=true sqlite=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
dupErr=0 javaDup=D2XYZ6
files/ 下无 .fmf2.wal/.wal.tmp/.fmf2.commit/.fmf2.tmp 残留
```

v2rayNG 2.4.0 回归：

```text
bootstrap ok state=4
bootstrapMs=929
MMKV 无 Permission denied
files/ 下无 WAL/提交/临时文件残留
```

## 限制

1. WAL 按块记录，随机写仍会重写整个受影响块。
2. 应用前校验需要读两遍 WAL；大文件 fsync 时延需按设备评估。
3. 目录 fsync 失败被吞掉，掉电场景不能对所有设备作绝对保证。
4. 跨进程写由文件锁串行化，没有多写者合并。
5. 旧 `FMJ1` 提交日志只做兼容恢复，新写入不再生成完整临时镜像。
6. `ShieldFiles` 输出已接入 FMF2/WAL；非 FMF2 旧文件首次写入会迁移为 FMF2。
