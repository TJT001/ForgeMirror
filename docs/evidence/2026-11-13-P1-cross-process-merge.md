# 2026-11-13 P1：跨进程写合并

## 范围

解决透明 I/O 的“最后关闭者覆盖”问题：多个进程各自持有 memfd 快照，
同步时不再把整份本地快照覆盖目标，而是按基线做分块三方合并，只写本地
真正修改过、且不与远端冲突的块。

## 实现

| 位置 | 内容 |
|---|---|
| `ShieldNativeIo.open` | 可写打开时记录 `baselineFileId`、`baselineChunkSize`、`baselineLength` 和每块 SHA-256 |
| `ShieldChunkStore.writeMerged` | 打开当前目标；若 `file_id`/块大小变化则退回 full 本地写入，否则执行 `merge` |
| `ShieldChunkStore.merge` | 读取目标当前块，和基线哈希比较；本地未改块直接保留，本地改块在无远端改动时写入；同块冲突 local-wins 并计数 |
| `ShieldNativeIo.persist` | 合并成功后刷新基线哈希/长度；只把合并结果交给增量 WAL |
| 测试探针 | 主进程持 memfd 写 chunk0，`:remote` 进程写 chunk2，主进程 close 时合并 |

### 合并规则

```text
localChanged = hash(local chunk) != baselineHash
remoteChanged = hash(target chunk) != baselineHash
```

- `!localChanged`：不写目标，远端修改保留；
- `localChanged && !remoteChanged`：写本地块；
- `localChanged && remoteChanged`：冲突，local-wins，计数并告警；
- 本地未改长度：保留目标当前长度（远端增长/缩短保留）；
- 本地改长度：本地长度获胜；若远端也改长度且不同，计冲突；
- 目标 `fileId` 或块大小变化：无法安全对齐基线，退回 full 本地写入；
- 目标缺失/损坏：退回 full WAL。

所有实际写入仍走 `FMW1` 增量 WAL，因此合并结果具备前滚/回滚能力。

## 验证

JVM（`ShieldChunkStoreTest` 26 项）：

- `crossProcessMergePreservesDisjointChunks`：本地 chunk0 + 远端 chunk2 均保留，0 冲突；
- `crossProcessMergeConflictKeepsLocalChunk`：同块冲突 local-wins 且冲突计数；
- `mergePreservesRemoteGrowthWhenLocalLengthUnchanged`：远端增长保留；
- 原有 WAL/恢复/截断/锁/重命名用例继续通过。

设备探针（Pixel 5 / API 30，主进程 + `:remote`；由前台的 `onResume` 启动远端服务）：

```text
MainActivity: merge probe ready
HarnessRemoteService: merge probe wrote remote pid=...
ShieldNativeIo: sync fd=62 bytes=200000 merged=true written=1 conflicts=0
ShieldNativeIo: sync fd=62 bytes=200000 merged=true written=0 conflicts=0
MainActivity: merge probe result writeErr=0 closeErr=0 main=MAIN remote=REMOTE
files/harness.txt magic: 46 4d 46 32 (FMF2)
readback: file=true append=true
```

第二次同步 `written=0` 说明合并后基线已刷新，不会把自身写入误判成远端冲突。
v2rayNG 2.4.0 回归 `bootstrap ok state=4`，MMKV 正常，无 WAL/commit/tmp 残留。

测试总计：Shield JVM 39 项、Python pipeline 65 项、Go `go test ./...` 通过。

## 限制

1. 冲突粒度是固定块，同块内不同字节的并发修改不会做字节级合并，local-wins；
2. 长度冲突同样是 local-wins，可能丢弃远端的截断/扩展结果；
3. 基线哈希在打开时捕获，不是分布式锁；文件被整体替换（`file_id` 变化）时退回 full 本地写入；
4. 跨进程仍由文件锁串行化，没有多写者同时应用 WAL；
5. `ShieldFiles` 已改为 FMF2/WAL，append 模式接入合并；非 append 保持截断语义（完整本地写入），不做远端合并。
