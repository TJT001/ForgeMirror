# 2026-11-13 P1：文件锁互操作（flock/fcntl）

## 范围

业务 native 代码对透明文件 fd（memfd）调用 `flock` 或 `fcntl` 锁时，锁只作用在
进程私有的 memfd 上，其他进程看不到。把锁操作映射到真实目标文件的独立
lock fd，使跨进程锁语义恢复。

## 实现

| 位置 | 内容 |
|---|---|
| `file_hooks.cpp` | 新增 `flock`、`fcntl` hook；`fcntl` 覆盖 `F_GETLK/F_SETLK/F_SETLKW`、`F_OFD_*`、`F_DUPFD/F_DUPFD_CLOEXEC` |
| `lock_fd_for` | 首次对 shadow fd 加锁时，用真实目标路径打开独立 lock fd（优先 `O_RDWR`，失败退回 `O_RDONLY`） |
| `gLockFds/gLockRefs` | shadow fd → lock fd 映射，按 lock fd 引用计数 |
| `dup/dup2/dup3/fcntl(F_DUPFD)` | 同步复制/迁移 lock fd 关系 |
| `proxy_close` | 释放当前 fd 的 lock 引用，最后一个引用关闭 lock fd |
| `try_shadow_open` | 记录 shadow fd 的真实路径，供锁映射使用 |

POSIX `fcntl` 锁是**进程级**的，同一进程内两个 fd 不互斥是内核语义；跨进程会
通过真实目标文件互斥。`F_OFD_SETLK` 是 open-file-description 级，可作为同进程
互斥验证。

## 验证

设备探针 `nativeProbeLock`：

- 两个 shadow fd 分别 `flock(LOCK_EX|LOCK_NB)` → 第二个 `EWOULDBLOCK`；
- 两个 shadow fd 分别 `F_OFD_SETLK` → 第二个失败；
- 普通 `F_SETLK` 首个成功（同进程 POSIX 语义），不要求第二个冲突。

```text
lockErr=0
readback ... file=true append=true ra=true mmap=true sqlite=true
merge writeErr=0 closeErr=0 main=MAIN remote=REMOTE
```

v2rayNG 2.4.0：`bootstrap ok state=4`，MMKV 正常，无 WAL/commit/tmp 残留。

## 限制

1. 同一进程内的 POSIX `fcntl` 锁按内核语义不互斥；跨进程才互斥。
2. lock fd 打在真实目标文件上，不直接复用 `ShieldChunkStore` 的内部 `.lock`
   文件；两套锁不声称互通。
3. 只覆盖常用 `fcntl` 命令；未知命令按无参透传，可能不适用于极少数厂商扩展。
4. 直接 `svc` 系统调用和 `io_uring` 仍绕过 libc hook，锁语义同样不覆盖。
5. `F_DUPFD` 之外的 `fcntl` 复制路径（如 `SCM_RIGHTS` 传递）未跟踪。
