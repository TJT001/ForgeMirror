# 2026-11-13 P1：原生透明 I/O、签名重验、文件监控与旧格式迁移

## 范围

libc 层透明文件读写（不再只拒绝写）、缺口语义补齐；APK 签名运行时重验；
关键状态文件 FileObserver 监控；DVE RC4 / `.edata` / `classes.dve` 旧格式检查与迁移。

## 实现

| 模块 | 内容 |
|---|---|
| `ShieldNativeIo.java` | 按策略读取明文，写入 **memfd**；`open` 直接返回 memfd fd；`sync` 在 fsync/close 时读回 memfd 并原子写 FMF2 |
| `file_hooks.cpp` | open 系列改为返回明文 memfd；close/fsync/fdatasync 回写；mmap/munmap/msync 跟踪并回写；`openat2`、`syscall.openat/open/ftruncate/mmap/openat2` 覆盖 |
| `ShieldIntegrity.java` | 运行时用 PackageManager 重验 APK 签名证书 SHA-256（`cert_sha256`） |
| `ShieldFileWatch.java` | FileObserver 监控 `files/shield` 的删除/移动/属性变化；忽略 `.tmp`/`.lock`；产生 `file_tamper` 事件 + Toast |
| `formats/file.py` / `legacy.py` / `cli.py` | DVE RC4 type 0/1 → FMF2；`.edata` / `classes.dve` 检查命令 |
| `protect.py` | 配置写入 `cert_sha256` |

## 透明 I/O 语义

- 覆盖路径：`files/**`、`shared_prefs/**`（按现有 policy）。
- `open/openat/open64/openat64/__open_2/__openat_2/openat2`：
  - 业务 native 调用方 → Java 读取明文写入匿名 memfd，返回 memfd fd；
  - `O_TRUNC` / `O_APPEND` / `O_EXCL` 按打开标志处理；
  - Java/框架内部调用与壳自身调用带 TLS 重入标记，不受影响。
- `read/write/pread/pwrite/lseek/ftruncate` 直接作用于 memfd。
- `mmap(PROT_WRITE)` 允许并记录映射；`msync/munmap/close` 时从 memfd 回写 FMF2。
- 无 kill/阻断路径；失败回退为拒绝（写）或原始打开（读）。

## 验证（Pixel 5 / API 30）

```text
readback prefs=true counter=2 file=true append=true ra=true mmap=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
      textErr=0 native=T2XYZ6 java=T2XYZ6
      mmapWriteErr=0 javaMmap=M2XYZ6
```

说明：

- 业务 so 的 `open/write/read` 得到明文，Java 侧立即读回同一内容；
- `mmap` 写入后经 `msync` 回写，Java 读到 `M2XYZ6`；
- `syscall(SYS_openat)` 同样透明；
- 文件最终恢复为原始内容，`ra/mmaps` 校验仍通过。

APK 签名重验通过（启动未进入恢复）；FileObserver 启动：

```text
ShieldFileWatch: watching /data/user/0/dev.forgemirror.demo/files/shield
ShieldFileWatch: tamper delete:server_config.json
ShieldEvents: recorded file_tamper/file_delete queued=1
ShieldResponse: response mode=toast kinds=tamper
```

旧格式工具：

```text
forgemirror migrate-file --input legacy.dve --out migrated.bin \
  --rc4-key <hex> --rc4-type 0 --key-file file.key
forgemirror legacy-inspect --edata .edata --dve classes.dve
```

### 测试

```text
ShieldDetectTest        3 项
ShieldChunkStoreTest    9 项
ShieldPolicyPatternTest 4 项
Python pipeline        59 项（含 RC4 向量、type0/type1 迁移、.edata/classes.dve 解析）
Go build / vet         通过
```

## 限制

1. memfd 语义与真实文件不同：`/proc/self/fd` 的 `readlink` 指向 memfd，`fstat` 元数据变化；依赖路径/元数据的 native 代码可能不兼容。
2. 跨进程各自持有独立 memfd 快照；并发写按文件锁串行，但最后关闭者覆盖，未做合并。
3. 进程崩溃时未 fsync 的写入丢失；无崩溃恢复日志。
4. `flock`/`fcntl` 锁作用在 memfd，不与真实文件锁互通。
5. 单文件上限 64 MiB；超大文件回退为原始打开/拒绝。
6. 内联 `svc` 直接系统调用、`io_uring` 仍未覆盖；`openat2` 的 `resolve` 语义未模拟。
7. 签名重验依赖 PackageManager，root/框架层伪造仍有边界；无 so 内存自校验。
8. 壳自身未实现双 `PT_DYNAMIC`/`DT_INIT` 自解密/字符串加密/系统调用桩——这是参考壳的架构，ForgeMirror 采用 FDX2 + 标准 linker，未按该路线重写。
9. `.edata`/`classes.dve` 只做检查，不自动应用 RC4 密钥；密钥需显式传入，未内置第三方壳常量。
