# 2026-11-13 P3：原生文件拦截层（libc inline hook）

## 范围

对覆盖路径的原生写打开、截断、重命名、删除、写映射和 `syscall()` 包装调用做拦截；
Java/框架内部调用与业务 native 调用分离，保证壳自身文件 I/O 正常。

## 实现

| 模块 | 内容 |
|---|---|
| `third_party/shadowhook/` | ShadowHook 2.0.1（MIT）源码，固定版本；仅 ARM/ARM64 构建 |
| `file_hooks.cpp` | `shadowhook_init` + 对 `libc.so` 多副本安装 hook；open/openat/open64/openat64/`__open_2`/`__openat_2`、close、rename/renameat、unlink/unlinkat、truncate/ftruncate、mmap/mmap64、syscall |
| `ShieldNativeFileHook.java` | 配置数据目录并启用拦截 |
| `ShieldRuntime.java` | bootstrap 阶段安装 hook |
| `native-lib.cpp` | 业务 so 侧探针：写打开、读打开、写 mmap、`syscall(SYS_openat)` |

## 拦截策略

- 覆盖路径：`<dataDir>/files` 与 `<dataDir>/shared_prefs`；相对路径按 `getcwd`/`dirfd` 解析。
- 只拦截**写语义**：`O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND`、`truncate/ftruncate`、
  `rename/unlink`、`PROT_WRITE` 的 `mmap`、`syscall.openat/open/ftruncate/mmap`。
- 调用方判定：`dladdr(shadowhook_get_return_address())` 指向 `/data/app`、`/data/data`、
  `/data/user` 的 native 库时拒绝；`/apex`、`/system`、`libshield*`、`libshadowhook` 放行。
- 被打开的文件 fd 记录在固定表，供 `ftruncate`/`mmap` 判断；`close` 时清除。
- 拒绝返回 `EACCES`，写 logcat `ShieldHook: deny <op> <path>`。

## 验证（Pixel 5 / API 30）

```text
ShieldHook: hook open in libc.so ok
ShieldHook: hook __open_2 in libc.so ok
ShieldHook: hook mmap in libc.so ok
ShieldHook: hook syscall in libc.so ok
ShieldRuntime: native file hooks status=0

readback prefs=true counter=1 file=true append=true ra=true mmap=true
probe writeErr=13 readErr=0 mmapErr=13 syscallErr=13

ShieldHook: deny __open_2 /data/user/0/dev.forgemirror.demo/files/harness_ra_renamed.txt
ShieldHook: deny mmap64 /data/user/0/dev.forgemirror.demo/files/harness_ra_renamed.txt
ShieldHook: deny syscall.openat /data/user/0/dev.forgemirror.demo/files/harness_ra_renamed.txt
```

- 业务 `libdemo.so` 的写打开、写 mmap、`syscall()` 打开均被拒绝（errno 13）；
- 读打开放行；
- Java 侧随机访问、mmap 快照、事件队列、跨进程锁均正常。

## 限制

1. **内联 `svc` 直接系统调用**不经过 libc 符号，当前 hook 无法覆盖；`openat2`、`io_uring`
   等新接口也未覆盖。
2. `syscall()` 拦截按 ARM64/ARM 的参数寄存器约定读取 6 个整型参数；带浮点参数的 syscall 不适用。
3. 仅构建 ARM/ARM64；x86/x86_64 shell 暂不支持（`abiFilters` 已限制）。
4. 业务 native 代码若合法需要读写覆盖路径，必须改走 Java facade；拦截默认拒绝，无按调用方豁免白名单。
5. 拒绝事件目前只写 logcat，尚未接入事件队列。
6. ShadowHook/内联 hook 受 ROM、ART、 linker 版本影响，需按设备矩阵验证。
7. `fopen`/`openat2`/`stat` 等未逐一 hook；写语义主路径已覆盖。
