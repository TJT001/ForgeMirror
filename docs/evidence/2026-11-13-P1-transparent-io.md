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

## P1 增补（2026-11-13 继续）

### 检测深度

- maps/线程特征扩展到 `dexposed`、`adbi`、`ddi`、`taichi`、`roothide`、`fupk3`、
  `dumpArtMethod`、`dumpDexFileByArtMethod`、`shadowhook`。
- 已知路径：`/data/local/tmp/frida-server*`、`/data/adb/modules/zygisk*`、`/riru*`、
  `/system/bin/.ext`、`/data/local/xbin`、`/system/sd/xbin`、`/data/local/bin`。
- `/proc/net/tcp`、`tcp6` 的 27042/27043 端口；`/proc/<pid>/cmdline` 的 frida 进程（权限允许时）。
- 调试器 watchdog：每 3 秒检查 `Debug.isDebuggerConnected`/`TracerPid`，首次命中上报一次。
- 排除壳自身 `libshield*`、`libshadowhook*`、YARA 扫描中的壳 so，避免自报。

### 响应分级

- 服务端 `client_config.policies`（JSONB）支持按 ruleId 指定 `log`/`toast`，迁移 `0005_client_policies.sql`。
- 客户端 `ShieldResponse` 按 `ruleId` 选择响应；未配置时回退全局 `response`。
- 设备：`file_tamper` 策略 `log` 时仅记录事件，不弹 Toast；`env_frida` 可单独设为 `toast`。
- 仍无 kill/exit/block；这是需求约束，不是遗漏。

### 多进程

- 新增 `ShieldDetectionBridge`：远端进程命中后通过包内广播送到主进程，由主进程记录事件并按策略响应。
- 主进程动态注册 `RECEIVER_NOT_EXPORTED`（API 33+）接收；主进程自身检测仍直接处理。

### YARA 模块

- 内置 MD5/SHA1/SHA256 fallback，启用 YARA `elf` 与 `hash` 模块；ELF 模块依赖的 TLSH 源码一并编入。
- host 侧校验：MD5/SHA1/SHA256 空串与 `abc` 向量全部匹配标准值。
- 扫描壳自身 so 时跳过 `libshield*`/`libshadowhook*`，避免九条规则误报。

### 兼容工具

- `edata-to-policy`：`.edata` → ForgeMirror policy JSON（rules/excludes/enc_type 报告）。
- `legacy-inspect --res-rule`：`KEY_RES_ENC` 重复 XOR 解码 + 长度/count/rules 最佳努力解析。
- 测试：Python 61 项；Shield JVM 17 项（Detect 4 / ChunkStore 9 / Policy 4）。

### 增补限制

- 多进程广播依赖包内动态接收器；主进程未启动时远端命中可能丢失。
- 端口/进程扫描受 Android 10+ `/proc` 权限限制，`/proc/net/tcp` 在部分 ROM 被 SELinux 拒绝。
- 响应仍只有 log/toast；block/degrade 未定义安全动作。
- YARA `pe` 模块仍因 crypto/PE 依赖未启用；`hash` 模块仅内置三种哈希。

### 响应档 `block`

- 服务端/客户端新增 `block` 档：命中后设置 native `gBlocked`，业务 native 对覆盖路径的
  `open/openat/open64/openat64/__open_2/__openat_2/openat2` 一律返回 `EACCES`。
- Java/框架调用（`gInternal` 或 libjavacore/libcore 等）不受影响，避免把壳自身 I/O 拦死。
- 设备验证：
  ```text
  ShieldFileWatch: tamper delete:events.seen.fmf
  ShieldResponse: response rule=file_tamper mode=block
  ShieldHook: blocked=1
  ```
  随后业务 native 的 `deny blocked` 生效；进程重启后解除。
- 仍无 kill/exit；`block` 是文件访问阻断，不是进程终止。

### 增补测试

```text
Python pipeline 61 项
Shield JVM      17 项
Go build/vet    通过
```

### 自检与反静态（本轮）

- 检测 token（frida/xposed/injection/unpacker/hook/thread/build）改为 XOR+hex 编码的
  `ShieldStrings` 风格常量，静态 DEX 中不再直接出现明文特征串；单元测试仍覆盖分类逻辑。
- `ShieldFileWatch` 增加 `files/` 父目录观察：`shield/` 目录被删除/移动时上报。
- `ShieldSelfCheck`：启动后检查 `/proc/self/maps` 是否映射 `base.apk`，以及可见的
  `libshield*`/`libshadowhook*` 映射是否来自 `sourceDir`/`nativeLibraryDir`；
  APK 内嵌 lib 在 maps 中通常只显示 `base.apk`，因此 `shellLibs=0` 计为可接受，
  发现 `(deleted)` 或非受信路径才上报 `file_tamper/self_check`。
- 设备：`ShieldSelfCheck: self check ok shellLibs=0`，无误报。

```text
ShieldSelfCheck: self check ok shellLibs=0
ShieldDetect: no runtime findings
ShieldDetectionBridge: registered
```

### 周期回写与递归监控（本轮）

- 透明 I/O 增加 dirty 跟踪：`write/pwrite64/writev/ftruncate/write mmap` 标记 shadow fd；
  后台线程每 2 秒调用 Java `sync`，把未 close 的 memfd 内容写回 FMF2，降低崩溃丢失窗口。
- 设备探针：native 线程持有 writable shadow fd 写入 `P2XYZ6` 并 sleep 5s，主线程 3s 后
  通过 Java facade 读回 `P2XYZ6`；日志可见周期 `sync fd=...`。
- `ShieldFileWatch` 改为递归扫描 `files/shield` 子树（深度 4），并保留 `files/` 父目录观察。
- 崩溃恢复仍非事务日志：最多丢约 2 秒未同步写入；>64 MiB 仍走拒绝/回退路径。

### `degrade` 档

- `degrade` 只阻断业务 native 对覆盖路径的**写打开**（`O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND`），
  读继续走透明 memfd；`block` 才阻断全部打开。
- 服务端/客户端策略值支持 `log` / `toast` / `degrade` / `block`。
- 设备：
  ```text
  ShieldResponse: response rule=file_tamper mode=degrade
  ShieldHook: block-mode=1
  ```
