# 2026-11-13 G1：P1 原型汇总（阶段状态）

## 四份原型报告

| 原型 | 报告 | 状态 |
|---|---|---|
| P1-A 构建侧 S0–S2 | `2026-11-12-P1A.md`、`2026-11-13-P1-self-decrypt-core.md`、`2026-11-13-P1-dt-init-lzss.md` | 完成 |
| P1-B 透明接管与恢复 | `2026-11-12-P1B.md`、`2026-11-13-P1-third-party-v2rayng.md` | 完成 |
| P1-C 完整 DEX 加载 | `2026-11-12-P1C.md`、`2026-11-13-P1C-plus.md`、`2026-11-13-P1C-plus-round2.md` | 完成（C1–C5） |
| P1-D 透明文件保护 | `2026-11-13-P1-transparent-io.md`、`2026-11-13-P1-D3-D5-C4-C5.md`、`2026-11-13-P1-journal-crash-recovery.md`、`2026-11-13-P1-cross-process-merge.md`、`2026-11-13-P1-lock-interop.md`、`2026-11-14-P1-memory-elf-loader.md` | 完成（D1–D5） |

补充：`2026-11-13-P1-double-dynamic.md`、`2026-11-13-P1-self-decrypt-core.md`、
`2026-11-13-P1-dt-init-lzss.md` 记录参考壳路线的静态对抗增强。

## P1 检查表

| ID | 状态 | 说明 |
|---|---|---|
| P1-A1–A6 | done | S0/S1/S2、容器自测、CLI、负例测试 |
| P1-B1–B6 | done | Provider/Factory/Application、幂等状态、Bootstrapper/Core、恢复页、S6 注入 |
| P1-C1–C3 | done | 内存 DEX、多 DEX 顺序、跨 DEX/反射/JNI/组件设备验证 |
| P1-C4 | done | `ShieldArt.Adapter` + `art-26-28` / `art-29+` 空适配器、运行时探测、单测 |
| P1-C5 | done（基线受限） | `bootstrapMs/firstFrameMs/decryptMs/pssKb`；见下文基线 |
| P1-D1–D2 | done | 策略通配/排除、SharedPreferences 适配 |
| P1-D3 | done | open/read/write/pread/pwrite/lseek/close + dup/dup2/dup3；mmap/msync |
| P1-D4 | done | 每文件 AEAD、逻辑偏移、原子迁移、排除直通 |
| P1-D5 | done（原型级） | 截断、残留 tmp、并发锁、重命名、排除 SQLite；FMF2 增量 WAL、崩溃恢复、跨进程分块合并与锁互操作 |
| P1-E | done | API/worker/PostgreSQL/Vue/开发授权 |

## 设备矩阵

| 设备/环境 | API/ABI | 结果 | 证据 |
|---|---|---|---|
| Pixel 5 | 30 / arm64-v8a | 通过 | demo 探针、v2rayNG 2.4.0、DT_INIT LZSS、诱饵、透明 I/O |
| Android 构建 | x86 / x86_64 | 仅编译通过 | ShadowHook/x86 原生 hook 未运行验证 |
| Pixel 5 | API 30 / armeabi-v7a | 通过 | 强制 32 位安装；ELF32 自研 loader、hook、dlopen 重定向、探针全通过 |
| API 26–28 | — | 未验证 | `ShieldInstrumentation` 路径未经真机 |
| API 37（Android 16） | arm64-v8a 模拟器 | 通过 | 默认保护/内存库探针全通过；`2026-11-14-P1-api37-hooks.md` |
| API 37 16 KB 页 | arm64-v8a 模拟器 | 通过 | `PAGE_SIZE=16384`；单 APK 与 AAB split 探针全通过；`2026-11-21-P2-16kb.md` |
| x86_64 16 KB | 构建/主机模拟 | 部分 | ELF/APK/AAB split 16 KB gate 通过；Dobby 静态后端编入 `libshield_hook`；Rosetta 下 loader 16 KB 模拟执行通过；无 x86_64 Android 运行镜像 |

结论：**已覆盖 Pixel 5 API 30（arm64 + armeabi-v7a）与 API 37 arm64 模拟器；API 26–28、x86/x86_64、国产 ROM 仍未覆盖。**

## 启动基线（Pixel 5 / API 30）

v2rayNG 2.4.0 冷启动：

```text
dex loaded count=5 decryptMs=749 pssKb=131310
bootstrapMs=985
firstFrameMs=2739
am start -W TotalTime=2915ms
```

Demo harness 的 `firstFrameMs` 包含 3 秒探针 sleep，不计入基线。

## 遗留项清单

| 类别 | 遗留 | 影响 |
|---|---|---|
| 崩溃恢复 | FMF2 已有增量 WAL + 前滚/回滚；旧 FMJ1 仅兼容；目录 fsync 尽力而为 | 掉电原子性未对所有 ROM 证明；`ShieldFiles` 已接入 FMF2/WAL |
| 并发 | 跨进程已做分块三方合并；同块冲突 local-wins，块级非字节级；多写者仍由文件锁串行应用 WAL | 同块并发修改会丢弃远端版本；无分布式锁 |
| 锁语义 | `flock/fcntl` 已映射到真实目标 lock fd；同进程 POSIX fcntl 仍按内核语义不互斥 | 不覆盖直接 `svc`/`io_uring`；不与内部 `.lock` 声称互通 |
| 系统调用 | 内联 `svc`、`io_uring` 未覆盖；`openat2.resolve` 未模拟 | 直接 syscall 可绕过透明 I/O |
| ABI | ARM32 已在 Pixel 5/API 30 验证；x86_64 完成 16 KB 构建/gate/loader 主机模拟和 Dobby 后端构建，但无运行镜像；x86 仅编译 | x86/x86_64 透明 I/O/block 未运行时验证；x86_64 使用 Dobby |
| 加载器 | 自研 ELF64/ELF32 loader（PT_LOAD/RELA/REL/RELR/DT_PLTREL/符号/GNU hash/INIT/RELRO/IRELATIVE/COPY）、DT_NEEDED 预加载与平台兜底、依赖 JNI_OnLoad、dlopen 重定向、唯一占位库、fail-closed 回退、safejni | TLS relocation、x86 真机未覆盖；JNI_OnLoad/dlopen 回退有短暂明文窗口 |
| ART | 适配器为空实现；直接 hook `ClassLinker::VerifyClass` 返回 true 在 API 30 触发 ART SIGABRT，已回退 | 需要安全的 class status 方案；当前无绕过证据，符合 C4 |
| 构建 | split APK 与 AAB split/universal 已支持；16 KB ELF/APK 对齐与 S8 校验已接入并在 ps16k 镜像验证；增量升级、按设备多 spec 共享优化仍未覆盖 | 见 `2026-11-21-P2-split-aab.md`、`2026-11-21-P2-16kb.md` |
| 设备 | API 26–28、31+、国产 ROM 未覆盖 | G1 矩阵不足 |

## 下一步建议

1. 建立 API 26/28/31/33/35 真机或云设备矩阵，优先验证 `ShieldInstrumentation` 与 ART 适配；
2. 为透明文件补事务 journal 与跨进程合并，再宣称崩溃一致性；
3. 评估 x86 原生 hook 后端（ShadowHook 不支持则明确 unsupported）；
4. 补内联 `svc`/`io_uring` 覆盖或明确记录为未覆盖路径。
