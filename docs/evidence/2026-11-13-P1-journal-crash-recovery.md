# 2026-11-13 P1：FMF2 事务日志与崩溃恢复

## 范围

为 `ShieldChunkStore`（FMF2）补提交日志与打开时恢复，覆盖持久化过程中的
崩溃窗口；正常路径不改变明文内容，只在文件旁增加 112 字节提交记录。

## 实现

| 位置 | 内容 |
|---|---|
| `ShieldChunkStore.persist` | 临时镜像 fsync → 计算 SHA-256 → 写 `.fmf2.commit` 并 fsync → 原子 rename → 目录 fsync → 删除日志 |
| `ShieldChunkStore.recover` | 获取文件锁后、读取目标前执行：前滚合法镜像、清理已应用事务、回滚坏日志 |
| `writeCommitFile` | 先写 `.fmf2.commit.tmp` + fsync，再原子改名，避免半条日志 |
| `ShieldFiles.ShieldFileOutputStream` | `close()` 改为幂等，避免 finalizer 二次 close 写入已关闭流 |

提交日志（`FMJ1`，112B）记录 txn id、镜像长度、明文长度、`file_id`、
临时镜像 SHA-256 和 footer txn id；日志不含明文。

## 崩溃窗口

```text
tmp 写入中        -> 无合法日志，删除 tmp，原目标可用
tmp fsync 后日志中 -> 日志无效，回滚
日志提交后 rename 前 -> 前滚（rename 临时镜像）
rename 后删除日志前 -> 目标哈希匹配日志，清理
日志删除后        -> 完成
```

目录 fsync 为尽力而为：部分 ROM/文件系统不允许只读打开目录。

## 测试

`ShieldChunkStoreTest` 18 项通过，新增：

- `committedJournalReplaysPreparedImage`：合法日志 + 准备好的镜像 → 前滚；
- `readOnlyOpenReplaysCommittedJournal`：只读打开也先恢复；
- `appliedJournalIsCleanedWithoutReplay`：目标已是新镜像 → 只清理日志；
- `truncatedJournalImageRollsBack`：镜像截断/哈希不匹配 → 保留原目标；
- `malformedJournalIsIgnored`：非法日志被忽略并清理；
- 既有 stale tmp、截断、并发锁、重命名用例继续通过。

设备回归（demo，Pixel 5 / API 30）：

```text
readback prefs=true counter=1 file=true append=true ra=true
         mmap=true sqlite=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
dupErr=0 javaDup=D2XYZ6
files/ 下无 .fmf2.commit / .fmf2.tmp 残留
```

v2rayNG 2.4.0 回归：

```text
bootstrap ok state=4
firstFrameMs=2671
MMKV 无 Permission denied
files/ 下无 .fmf2.commit / .fmf2.tmp 残留
```

测试总计：Shield JVM 31 项、Python pipeline 65 项、Go `go test ./...` 通过。

## 限制

1. 日志引用完整临时镜像，不是按脏块的增量 WAL；每次持久化仍复制未修改块。
2. 目录 fsync 失败被吞掉，掉电场景不能对所有设备作绝对保证。
3. 跨进程写由文件锁串行化，没有多写者合并。
4. 只覆盖 FMF2 持久化；`ShieldFiles` 的 `.tmp` 原子替换未接入同一日志。
