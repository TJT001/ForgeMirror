# libDexHelper.so 架构还原文档（v2.0，2026-11-11）

> **最新全量进度汇总见 §45**（自解密 / DEX 容器解密 14/14 / classes.dve / info.y=YARA 规则 / .edata / DVE 文件加密 / 壳引擎规则命中验证均已打通）。

- 样本：`libDexHelper.so`（arm64），参照样本 A `com.example.reference`
- 文件 SHA-256：`d7455105a14ae87bc76e3f5db04e5bdcfd1f4fa7b5949d4a8f49ed623fc4ebdd`
- 文件大小：979,501 字节；依赖：`libandroid.so` `liblog.so` `libz.so` `libm.so` `libdl.so` `libc.so`
- 本文日期：2026-11-11
- 结论级别标记：**[观测]** 直接证据（字节/反编译/字符串）；**[推断]** 由证据推导；**[未知]** 未证实

---

## 0. 结论摘要

1. 这个 `.so` 是梆梆 SecNeo 壳自带的 **加载器/保护运行时**，不是普通业务库：它负责解密自身代码段、重建可执行映射、从内存加载 DEX、解析 ART 符号绕过系统类加载、并执行多路反调试/反 Hook 检测。
2. **静态文件首段是加密的**：文件偏移 `0x2ad10 ~ 0xc7140` 与运行时内存镜像不一致；运行时镜像在 `dumps/dexhelper_mem.bin`（此前动态 dump）中为明文。本文的深度分析基于"静态 ELF + 运行时首段覆盖"重建的 `analysis/libDexHelper/libDexHelper.dec.so`。
3. **ELF 元数据是「双份 dynamic」**：`PT_DYNAMIC.p_offset` 指向诱饵表（只剩 `NEEDED`/`SONAME`），`p_vaddr` 指向真表（含 `INIT/SYMTAB/STRTAB/RELA`）。linker 按 `p_vaddr` 读，所以能正常加载；静态工具按 `p_offset` 读会误判。section 名表同样被破坏。**[观测]**
4. 壳的功能面可归为七块：**自解密引导、JNI 适配层、DEX 内存加载、ELF 加载器（libelf）、压缩/解压（zlib/zstd/LZMA）、检测与自毁、文件监控（inotify）**。
5. 检测目标覆盖：Zygisk、Frida、Xposed/Dexposed、ADBI/DDI 等 Hook 框架、调试器（TracerPid/ptrace）、模拟器/多开、ART 内存符号扫描。
6. **直连 syscall 表**：`0xee1xx`（vaddr `0xef1xx`）区存在 `mov x8,#N; svc #0; ret` 形式的直接系统调用桩，含 `openat(56)`、`close(57)`、`read(63)`、`write(64)`、**`exit_group(94)`**，用于绕过 libc 层 Hook；`exit_group` 桩位于文件偏移 `0xee1dc`（vaddr `0xef1dc`）。**[观测]** 桩存在；**[未知]** 调用者与索引方式（未见直接 xref）。
7. 前几轮动态报告中"退出路径找不到"的最后一环，与第 6 条高度吻合：壳很可能通过自己的 syscall 表直接执行 `exit_group(0)`，不经过 libc 的 `exit`/`_exit`。

---

## 1. 取证与重建方法（可复现）

| 步骤 | 命令/文件 | 结果 |
|---|---|---|
| 1 | `unzip -j apk_pull/base.apk lib/arm64-v8a/libDexHelper.so -d analysis/libDexHelper/` | 得到静态文件 |
| 2 | 对比 `dumps/dexhelper_mem.bin`（运行时镜像，937,984 B）与静态文件 | 前 `0x2ad10` 一致；`0x2ad10~0xc7140` 大片不同；其后零散差异为运行时重定位 |
| 3 | 用运行时镜像覆盖静态文件首段：`dec[0:0xe3810] = mem[0:0xe3810]` | 得到 `libDexHelper.dec.so`（SHA-256 `c37fabca…6523`），`0x51024` 处可正常反汇编 |
| 4 | IDA headless（idalib 9.3）自动分析 | 272 个函数（190 个是导入桩） |
| 5 | 因为首段被标成 data，IDA 不建函数；用 `analysis/tools/ida_force_dump.py` 设置段可执行 + `auto_make_code` + `add_func` | 1,955 个函数，1,762 个出伪代码 |
| 6 | 产物 | `analysis/libDexHelper/ida_force/functions/*.c`、`functions.json`；早期导出在 `pseudo_dec/` |

> 注意：IDA 的强制建函数会带来一定误报（数据被当成代码），关键结论均回到字节级/调用链复核。

现有动态证据沿用：
- `dumps/dexhelper_mem.bin`（首段明文镜像）
- `fart_dump/`、`unpacked/`（DEX 产物，两路 MD5 一致）
- `检测函数定位与绕过说明.md`（运行时检测点与退出观测）

---

## 2. ELF 结构与加固特征

### 2.1 段布局 **[观测]**

| 段 | 文件偏移 | 虚拟地址 | 文件大小 | 内存大小 | 权限 | 状态 |
|---|---|---|---|---|---|---|
| LOAD#1 | `0x0` | `0x0` | `0xe3810` | `0xe3810` | R-X | **文件内加密**（`0x2ad10` 起） |
| LOAD#2 | `0xe4270` | `0xe5270` | `0x8e58` | `0x21e90` | RW- | 数据/系统调用桩表 |
| LOAD#3 | `0xee078` | `0x108078` | `0xafc` | `0xafc` | R-X | **明文引导段** |

- 文件内只有这 3 个 `PT_LOAD` + 1 个 `PT_DYNAMIC`（位于 LOAD#2）。**[观测]**
- **`PT_DYNAMIC` 是双份的**：`p_offset`（文件 `0xeeb90`）指向一张只有 `NEEDED`/`SONAME` 的**诱饵表**；`p_vaddr`（`0xe8750`）对应的文件偏移 `0xe7750` 才是**真表**：
  `DT_INIT=0x108098`、`DT_INIT_ARRAY=0xe5270`（内容 `0x2d230`）、`DT_SYMTAB=0x5290`、`DT_STRTAB=0xdff0`、`DT_GNU_HASH=0x29e0`、`DT_RELA=0x1d6d8`、`DT_RELASZ=0x9eb8`、`DT_JMPREL=0x27590`。**[观测]**
- Android linker 按 `p_vaddr` 取 dynamic，所以能正常加载；静态工具若按 `p_offset` 读就会误判为「动态表被抹除」。**[观测/推断]**
- section header 名表损坏（REA 的 `inspect_native_exports` 报 `ELF section name table is not a string table`）。**[观测]**

### 2.2 真实加载流程 **[观测]**

```
Android linker（System.loadLibrary("DexHelper")）
  ├─ 按 PT_LOAD 映射 3 个段（首段此时仍是密文）
  ├─ 读真 dynamic（p_vaddr=0xe8750）：应用 RELA/JMPREL 重定位
  ├─ 调用 DT_INIT = 0x108098（明文尾段）
  │    ├─ 读 /proc/self/maps 自检，失败 → exit_group(94)（0x108380）
  │    ├─ mmap RWX + 解密首段（区间解码 + 4 字节 XOR）
  │    ├─ 刷 I-cache
  │    ├─ 按程序头 mprotect 各段
  │    └─ 应用迁移/重定位表 sub_1083AC
  ├─ 调用 DT_INIT_ARRAY[0] = 0x2d230（此时已被解密）
  │    └─ C++ 静态构造（start：连续 sub_2D1D0 / sub_2C870）
  └─ dlsym("JNI_OnLoad") → 0x2f7f0（dynsym 在明文区，静态可查）
```

结论：不是「自定义加载器」，而是**标准 linker + DT_INIT 自解密 + 诱饵 dynamic 表**。这解释了 `System.loadLibrary("DexHelper")` 为何能直接成功，也解释了运行时是 file-backed 映射（首段在映射内被原地解密）。

### 2.3 字符串与符号

- `0xe000~0x1b000` 区保留大量 **C++ mangled 名称字符串**（`DexFileLoader::Load*`、`safejni::invoke*`、`JNIException`、`inotifytools_*`、`elf__load` 等），说明动态符号名以字符串形式被保留/重建。**[观测]**
- 关键全局名：`g_sym_JNI_OnLoad`、`libc_ptrace`、`dexflag`、`multidex_entry`、`g_sdkVer_forhook`、`wrapHook`、`hookFunAddr_read`。**[观测]**

---

## 3. 启动与引导链

### 3.1 两段式执行顺序 **[推断]**

```
libdexjni / 壳加载器
  → 明文引导段（0x108078..0x108b74）
      .init_proc(0x108098)
        → sub_1087DC(源结构, 加密首段)
            → sub_10818C(mmap RWX)
            → memcpy
            → sub_108224(icache flush)
        → loc_10850C(源结构, &qword_2AD10, size)
  → 主段可用后，ART 调用 JNI_OnLoad(0x2f7f0)
```

> 说明：`init_proc` 的反编译把参数压成了两个调用，`loc_10850C` 不是 IDA 认可的函数（`Not a function`），其真实签名需按寄存器级复核。**[未知]**

### 3.2 `JNI_OnLoad`（`0x2f7f0`，8300 字节）**[观测]**

行为序列（来自伪代码）：

1. `(*vm)->GetEnv(vm, &env, 0x10004)`（JNI 1.4）；失败返回 `-1`。
2. `FindClass("com/secneo/apkwrapper/H")`，随后 `RegisterNatives(H, table, 3)`。三个方法签名从栈上常量可读出：
   - `(Ljava/lang/String;)I`
   - `(Ljava/lang/String;I)V`
   - `(I)V`
   （常量位于 `0xc5b45` 附近的字符串区；方法名被拆分构造）
3. 连续调用 `sub_2BD40` / `sub_2CA60` / `sub_2CE10` / `sub_2B9D0`，把解密结果写入一批全局：
   `qword_F1430`、`qword_F1440`、`qword_F15A8`、`qword_F15B8`、`qword_F1578`、`qword_F1590`、`qword_F1458`、`qword_F13F8` …
4. 初始化 SDK/ART 描述结构 `qword_F13F8`：写入 `"arm64"`，并构造 `com/secneo/apkwrapper/H` 与 `com/secneo/apkwrapper/AW` 的类名字段。
5. 后续分支（伪代码 300 行之后）继续解密参数、调用 `H` 的方法、初始化检测线程。**[部分观测]**

结论：`JNI_OnLoad` 是壳的**总装入口**，负责把"字符串/配置/类名/ART 版本"准备好，然后启动 DEX 加载与检测。

---

## 4. 功能子系统

### 4.1 字符串与常量解密

| 地址 | 名称 | 证据 |
|---|---|---|
| `0x2f628` | `so_postfix_wrap(void*, int)` | RC4 KSA（256 字节 S 盒）+ 逐字节 XOR 解密，末尾调用 `sub_BEDB8`；**[观测]** |
| `0x2BD40` / `0x2CA60` / `0x2CE10` / `0x2B9D0` | 字符串取用/解密辅助 | 被 `JNI_OnLoad` 高频调用，结果写入全局指针 + 长度，随后补 `\0`；**[观测]** |
| `0x108914` | 区间解码器（range coder） | 与 LZMA 解码器结构一致（`0x7FFFFFFF` 归一化、位概率模型）；**[推断]** |

### 4.2 JNI 适配层

字符串区保留完整的方法名，可据此定位实现：

- `safejni::invoke` / `invokeStatic` / `AllocObjectAPI` / `NewObjectAPI` / `getStaticFieldAPI` / `setObjectFieldAPI`
- `Utils::getMethodInfo` / `getStaticMethodInfo` / `toJString` / `dumpReferenceTable` / `checkException`
- `JNIException` / `throwJavaExcpetion` / `catchMethod`
- `addLocalRef` / `deleteLocalRef`（对 8 种数组类型各有重载，配合 `unordered_map<jobject,int>` 做本地引用管理）
- `JNIMethodInfo`、`lookup(JNINativeMethod*, name, sig, &fn)`（`0x2f074`）

作用：**绕开 Frida 等工具对 JNI 函数的 Hook**，同时稳定管理 LocalRef 生命周期。**[推断]**

### 4.3 DEX 内存加载（核心）

| 地址 | 名称 | 说明 |
|---|---|---|
| `0x2e810` | `DexFileLoader::DexFileLoader(void*, int)` | 构造 |
| `0x2e820` | `DexFileLoader::Load()` | 按 `qword_F13F8` 中的 SDK 版本分派 |
| `0x2e904` | `LoadV26()` | 解析 `art::DexFile::OpenCommon` |
| `0x2ea54` | `LoadV28()` | 同上（新版签名） |
| `0x2ed50` | `LoadV34_BETA1()` | Android 14 Beta 变体 |
| `0x2ef18` | `LoadV34_DP2()` | Android 14 DP2 变体 |
| `0x2f06c` | `dexFile()` | 取加载结果 |

机制链 **[观测 + 推断]**：

1. `Load()` 读取 `qword_F13F8` 的版本字段（另含 `+20` 的版本），对 26/28/34 分派。
2. `LoadV26()` 解析 ART 导出：
   - `art::DexFile::OpenCommon(...)`
   - `art::DexFile::OpenMemory(...)`（多版本签名）
   - `art::ArtDexFileLoader::Open(...)`
   - 通过内部 `sub_390E8(handle, mangled_name)` 做 `dlsym` 式解析。
3. 用解析到的函数指针把内存中的 DEX 直接交给 ART（`Anonymous-DexFile` / `AnoymousDex`），绕开 `DexClassLoader` 的路径校验与文件落盘。
4. 相关字符串：`dexdata0`、`dexCache`、`classes%d.dex`、`multidex_entry`、`base64_decode`、`Dalvik/system/InMemoryDexClassLoader`、`makeInMemoryDexElements`。
5. 旧版兼容：`dvmRawDexFileOpenArray`、`dalvik/system/DexFile.loadDex`、`DexPathList`/`Element`。

DEX 数据的解密/解压尚未定位到具体函数 **[未知]**，但候选组件包括 zlib、zstd、LZMA 与 RC4。

### 4.4 ELF 加载器（libelf 移植）

字符串与函数名完整暴露：

- `elf__initialize` / `elf__load` / `elf__unload` / `elf__finalize`
- `parse_elf_header_{32,64}_{le,be}`、`elf_rva_to_offset_{32,64}_{le,be}`
- `hex_yyalloc` / `hex_yyfree` / `hex_yyrealloc`（libelf/elfutils 的选项解析）

用途：解析并映射随包携带的原生库（`libdatajar.so`、`libaoc.so` 等字符串），实现**内存加载 .so**，不经过 `dlopen` 的文件路径校验。**[推断]**

### 4.5 压缩与解压

- zlib：`zip 1.01 Copyright 1998-2004 Gilles Vollant`、导入 `deflateEnd`。**[观测]**
- zstd：`g_ZSTD_threading_useless_symbol` 符号存在。**[观测]**
- LZMA：`0x108914` 的区间解码结构与 LZMA 一致。**[推断]**

### 4.6 线程、同步与文件监控

- `create_thread` / `thread_join`、`mutex_init/lock/unlock/destroy`、`semaphore_init/wait/release/destroy`、`pthread_*`。
- 全局锁：`output_mutex`、`queue_mutex`。
- inotify 工具库：`inotifytools_watch_file(s)`、`inotifytools_watch_recursively(_with_exclude)`、`inotifytools_next_event`、`remove_inotify_watch`，以及 `/proc/sys/fs/inotify/max_user_watches` 读取。
- 事件常量 `DELETE_SELF`、`MOVE_SELF` — 说明会对自身文件/目录做**删除/移动监控**（反卸载/反替换）。**[观测]**

### 4.7 日志与错误

- `[SECSDK] received signal %d !!!`（`0xc46a9`）
- `[SECSDK]` 前缀、`g_debuglevel` 全局。
- `JNIException` 体系与 `std::__libcpp_tls_set failure` 等 libc++abi 字符串 → 静态链接了部分 libc++abi。

---

## 5. 检测子系统（地址 -> 目标）

| 地址 | 大小 | 检测目标 | 证据 |
|---|---|---|---|
| `0x51024` | 2212 | **Zygisk**：`"zygisk.so"`、`"zygisk_s..."`、`/system/bin/.ext`、`/data/local/xbin`、`/system/sd/xbin`、`/data/local/bin` | 伪代码含 `strcpy(...,"zygisk.so")`；`0xc2658` 字符串块 |
| `0x50248` | 3464 | **`/proc/self/maps` 扫描器**：入参含 2 个回调（匹配/命中处理） | 函数签名 `(buf, len, count, cb1, cb2)`；`"failed to open maps"`（`0xc821e`） |
| `0x4B4F0` | 13568 | **ART 符号扫描**：`/proc/self/maps` + `AddGlobalRef`/`VisitClassLoaders` 等符号匹配（既有动态报告 `+0x4b9c4` 落在此函数内） | 与 `检测函数定位与绕过说明.md` §8.1 对齐 |
| `0x2DBC0` | — | **环境关键字表**：`usb` `appmo` `proxy` `emu` `polling` `inject` `frida` `debug` `rom` `xposed` `integrity` `signature` `display` | 伪代码逐条 `strcpy` 构造；这解释了此前把它误认成"处置函数"的问题 |
| `0x530B0` | — | **Frida 相关检查**（字符串 `frida_agent_main` 等） | grep 命中 |
| `0x54704` / `0x552A4` | — | **`/proc/<pid>/status`、TracerPid、调试状态** | grep 命中 |
| `0x4EA10` | — | 环境/Hook 综合检查（引用 frida 字符串） | grep 命中 |
| `0x59C24` / `0x597F0` | — | DEX 数据结构（`dexdata0`/`dexCache`） | grep 命中 |

配套字符串（`0xc482a~0xc495a`，反 Hook 名单）：

```
adbi_hook, ALLINONEs_arthook, ddi_hook, dexposed,
hook_postcall, hook_precall, dalvik_java_method_hook,
art_java_method_hook, dexstuff_defineclass, dexstuff_loaddex,
dexstuff_resolv_dvm, DexposedBridge, dexposedIsHooked,
dexposedCallHandler, frida_agent_main
```

其他检测素材：

- `/proc/%d/maps`、`/proc/%ld/status`、`/proc/%ld/task`、`/proc/%ld/cmdline`、`/proc/%ld/net`、`/proc/self/cmdline`、`/proc/self/mounts`
- `TracerPid`、`ptrace`（全局 `libc_ptrace`）
- `/system/bin/`, `/system/xbin/`, `/data/local/xbin/`、`/su/bin/`、`/data/daemon/`
- `android/os/Debug`、`debug.atrace.tags.enableflags`、`/sys/kernel/tracing/trace_marker`、`/sys/kernel/debug/tracing/trace_marker`
- 模块白名单正则：`^/apex/.*/libart\.so$`、`^/system/.*/libbinder\.so$`、`^/apex/.*/libperfetto_hprof\.so$` 等

---

## 6. 自毁与 syscall 直通

### 6.1 系统调用桩与"双映射" **[观测]**

文件偏移 `0xee1a0` 起的一段字节被**同时映射两次**：

| 映射 | 虚拟地址 | 权限 | 用途 |
|---|---|---|---|
| LOAD#2 | `0xef1a0` | RW- | 数据别名；符号表里登记为 `multidex_entry`（+0x18）与 `v1jar_mapaddr`（+0x8） |
| LOAD#3 | `0x1081a0` | R-X | 可执行别名；引导代码用 `BL 0x1081xx` 直接调用 |

同一段字节里的桩（按 `mov x8,#N; svc #0; ret` 解码）：

```
0x1081a0 (vaddr)  mprotect  (226)
0x1081ac          write     (64)
0x1081b8          read      (63)
0x1081c4          openat    (56)
0x1081d0          close     (57)
0x1081dc          exit_group(94)
```

> 修正：此前把这段称为"通用 syscall 直通表"不准确。它是 **bootstrap 运行时自带的最小 syscall/字符串库**，同时被登记为 multidex 相关数据符号。主代码段（`0x2ad10` 起）不直接 `BL` 这些地址，而是走 libc。

### 6.2 其他退出出口 **[观测]**

- 动态报告记录的内联 `kill(pid,9)` 6 处、`exit_group` 存根 1 处、两处跳转改 epilogue、`+0x55068` 越界写，均已在 `bypass_final.js` 覆盖。
- 注意：这些偏移是**运行时镜像偏移**，与本文静态偏移在首段加密区一致（dump 与文件同基），可直接对照。

---

## 7. 分层架构图（推导）

```
┌────────────────────────────────────────────────────────────┐
│ Java 层                                                    │
│  com.secneo.apkwrapper.AW / H                              │
│  InMemoryDexClassLoader / DexPathList / DexFile             │
└───────────────▲────────────────────────────────────────────┘
                │ JNI（RegisterNatives, 3 个方法 + safejni 封装）
┌───────────────┴────────────────────────────────────────────┐
│ JNI 适配层                                                 │
│  safejni::invoke/invokeStatic、JNIMethodInfo、JNIException  │
│  addLocalRef/deleteLocalRef、Utils::getMethodInfo           │
├────────────────────────────────────────────────────────────┤
│ DEX 加载器                                                 │
│  DexFileLoader::Load → V26/V28/V34_BETA1/V34_DP2            │
│  通过 dlsym 解析 art::DexFile::OpenMemory/OpenCommon        │
│  内存 DEX：dexdata0 / Anonymous-DexFile / multidex_entry    │
├────────────────────────────────────────────────────────────┤
│ 通用运行时支撑                                             │
│  ├─ 字符串解密（RC4 0x2f628 + 辅助函数）                    │
│  ├─ 压缩：zlib / zstd / LZMA(0x108914)                      │
│  ├─ ELF 加载：libelf 移植（elf__load / parse_elf_header_*） │
│  ├─ 线程/锁/信号量、inotify 文件监控                        │
│  └─ 直接 syscall 表（0xee1xx）                              │
├────────────────────────────────────────────────────────────┤
│ 检测与响应                                                 │
│  0x51024 Zygisk │ 0x50248 maps │ 0x4B4F0 ART 符号          │
│  0x2DBC0 环境关键字 │ 0x530B0 Frida │ 0x54704/0x552A4 调试 │
│  → 命中后：自毁（kill/exit_group）或标记                    │
├────────────────────────────────────────────────────────────┤
│ 引导层（明文尾段 0x108078..）                              │
│  mmap RWX → memcpy 解密首段 → icache flush → 修复动态表     │
└────────────────────────────────────────────────────────────┘
```

---

## 8. 与既有动态结论对照（含更正）

| 既有结论 | 本文证据 | 处置 |
|---|---|---|
| `+0x51024` 是 Zygisk 检测 | 伪代码里 `"zygisk.so"`、`.ext`/`xbin` 路径 | **确认** |
| `+0x50248` 是 maps 扫描器 | 2 个回调参数的扫描函数；`"failed to open maps"` | **确认** |
| `+0x4b9c4` 是 ART 符号扫描 | 落在 `sub_4B4F0`（13568 B）内 | **确认** |
| 退出不经 libc、无信号、干净退出 | 发现 `exit_group(94)` 直调桩 `0xee1dc` | **新证据**，指向直连 syscall |
| `0x2dbc0` "命中后进入处置分支"需重新核对 | 该函数实际在构造 `usb/emu/frida/xposed/...` 关键字表 | **更正**：它是检测**输入构造**，不是处置入口 |
| `.text` 加密进 file-backed RWX 映射 | 静态文件 `0x2ad10~0xc7140` 与运行时镜像不同 | **确认**（静态加密、运行时明文） |

---

## 9. 未解决问题（按优先级）

1. **`exit_group` 桩的调用者**：表基址如何取得、索引如何计算、命中后由哪个检测函数触发。
   - 建议：对 `0xee1xx` 表做内存写断点（运行时），或在首段全量扫描 `ldr xN,[xM,#imm]` 后 `blr` 的间接调用点。
2. **DEX 解密算法与密钥**：~~`dexdata0` 段的头部结构、密钥来源（类名/设备信息/固定常量）~~
   **已解决（见 §39）**：标准 SM4-ECB，密钥 = so 常量 ⊕ 包名前 16 字节，仅前 0x20000 加密、
   其余明文，14/14 DEX 与动态捕获 MD5 一致。
3. **动态表修复细节**：`loc_10850C`（`0x10850c`）真实签名与它如何重建 `DT_STRTAB/DT_SYMTAB/DT_RELA`。
4. **完整性校验**：`manifest.mf`/`rsa.sig` 校验路径是否在本 so 内（当前只见 `integrity`/`signature` 关键字）。
5. **JNI 导出全集**：除 `JNI_OnLoad` 外，是否存在 `Java_*` 导出（静态 dynsym 已抹除，需要运行时 `JNI_OnLoad` 断点确认）。
6. **检测命中阈值**：各检测函数返回值如何汇总到"退出"决策（`0x50248` 的 cb2？）。
7. **误报治理**：强制建函数得到的 1,955 个函数中，需按"含 BL/RET + 被引用"过滤出真实函数集。

---

## 10. 证据与产物索引

| 产物 | 路径 |
|---|---|
| 静态样本 | `analysis/libDexHelper/libDexHelper.so` |
| 解密重建镜像 | `analysis/libDexHelper/libDexHelper.dec.so` |
| IDA 伪代码（全量强制） | `analysis/libDexHelper/ida_force/functions/*.c` + `functions.json` |
| IDA 伪代码（自动分析） | `analysis/libDexHelper/pseudo_dec/functions/*.c` |
| 字符串清单 | `analysis/libDexHelper/strings_all.txt`、`strings_selected.txt` |
| 运行时常量/检测点 | `检测函数定位与绕过说明.md`、`参照样本A_加固与反调试绕过.md` |
| 工具脚本 | `analysis/tools/ida_dump.py`、`ida_force_dump.py`、`unpack.py`、`lzss_decode.py`、`sm4.py`、`fdex_unpack.py`、`dve_rc4.py`、`unicorn_dve.py`、`unicorn_hash.py`、`rename_imports.py`、`ida_retype_dump.py`（完整索引见 §45.4） |
| 解释器 | IDA 9.3 idalib + REA 6.8.0（`REA_IDA_MCP_CONFIG=~/.local/share/rea/ida-mcp.json`） |

---

## 附录 A：关键函数速查

| 地址 | 大小 | 名称/推断作用 |
|---|---|---|
| `0x108098` | 220 | `.init_proc`：引导入口 |
| `0x10818C` | 90 | `mmap` syscall 封装 |
| `0x108224` | 104 | I-cache/D-cache 刷新 |
| `0x1082A8` | 3273 | 引导段解析/搬移（待细读） |
| `0x10850C` | — | 引导第二步（动态表修复候选） |
| `0x1087DC` | 289 | RWX 分配 + 拷贝 + flush |
| `0x108914` | 6299 | 区间解码器（LZMA 类） |
| `0x2E810` | 16 | `DexFileLoader` 构造 |
| `0x2E820` | 228 | `DexFileLoader::Load`（版本分派） |
| `0x2E904` | 336 | `LoadV26` |
| `0x2EA54` | 352 | `LoadV28` |
| `0x2ED50` | 456 | `LoadV34_BETA1` |
| `0x2EF18` | 340 | `LoadV34_DP2` |
| `0x2F074` | 124 | `lookup(JNINativeMethod*, ...)` |
| `0x2F628` | 456 | `so_postfix_wrap`（RC4 解密） |
| `0x2F7F0` | 8300 | `JNI_OnLoad` |
| `0x2DBC0` | — | 环境关键字表构造 |
| `0x4B4F0` | 13568 | ART 符号 / maps 深层扫描 |
| `0x50248` | 3464 | maps 扫描器（带回调） |
| `0x51024` | 2212 | Zygisk 检测 |
| `0x530B0` | — | Frida 相关检查 |

> 伪代码中大量 `pS_...` 形式的名字来自被保留/重建的 mangle 名称或 IDA 自动命名，不代表真实符号；以地址与行为为准。

---

## 附录 B：下一步建议

1. 先做 **函数可信度过滤**：仅保留"包含 BL 或 RET + 被其它函数引用 + 可反编译"的集合，产出 `functions_clean.json`。
2. 针对第 9 节第 1 条，用 Frida 在 `0xee1dc` 下 `MemoryAccessMonitor`（或内存断点）定位调用者。
3. 针对 DEX 解密，从 `LoadV26` 的入参（`DexFileLoader` 对象 `a1`）回溯 `dexdata0` 的填充点。
4. 用 `JNI_OnLoad` 的 `H` 注册点做运行时插桩，确认三个 native 方法的实际用途。

---

## 11. v0.2 增补（2026-11-11 二次分析）

### 11.1 引导链已解出 **[观测]**

`sub_1085EC` 是自加载的核心，伪代码与汇编一致：

1. **返回地址自检（反 Hook）**：函数把 `x30`（返回地址）当数据指针，与 3 段各 10 字节的常量比较：
   - 返回地址处内嵌字面量：`"__b_a_n_g_c_l_e__check1234567_"`（位于 `0x1085cc`）
   - `0x108b28`=`"__b_a_n_g_"`、`0x108b33`=`"c_l_e__che"`、`0x108b3e`=`"ck1234567_"`
   三段全匹配才继续解密；任一不符 → `sub_1082A8(标记指针)` 扫 `/proc/self/maps`，失败即 `exit_group(94)`。
   即：**校验调用点地址上的字节是否被改动**（防止 inline hook / 重定位劫持）。**[观测]**
2. **maps 失败即退出**：`sub_1082A8` 打开 `/proc/self/maps`，逐行读取（512 字节缓冲），在行内按"首字节 + 剩余串"匹配标记；**读到 EOF 仍未命中时，在 `0x108380` 直接 `BL 0x1081dc`（exit_group(94)）**。这是壳的 fail-closed 路径之一。**[观测]**
3. **解密主段**：
   - `mprotect(page, size, 7)`（`0x108690`）
   - `sub_1088F0(目标, 源, len, key)` → 调用 `0x108914`（区间解码器 / LZMA 类）**[观测]**
   - 逐 4 字节异或：`*(u32*)(dst + off + i) ^= v11`（`v11` 为长度/密钥字段）**[观测]**
   - `sub_108224` 刷 I-cache **[观测]**
4. **修复段权限**：解析 ELF 程序头（`e_phoff = *(u32*)(base+32)`，`e_phentsize = *(u16*)(base+54)`，`e_phnum = *(u16*)(base+56)`），对两个 PT_LOAD 分别 `mprotect(..., 3)`。**[观测]**
5. **重定位**：`sub_1083AC(reloc_array, reloc_data, count, base)` —— 分配临时页、读 4 字节重定位项、`*(u32*)(base + r_offset) = value`、清零源数组、`munmap`。**[观测]**
6. `sub_108180` 释放临时内存。**[观测]**

`sub_1087DC`（`.init_proc` 调用）则负责：按源结构 `+0x28` 取长度 → `mmap(NULL, len, 7, 0x22)`（RWX）→ 逐字节拷贝 → `sub_108224` 刷缓存。**[观测]**

### 11.2 运行时符号表已恢复 **[观测]**

- 位置：**以真 dynamic 的 `DT_SYMTAB=0x5290` 为准**，共 `1508` 条 `Elf64_Sym`，字符串表 `DT_STRTAB=0xdff0`；其中 `1315` 条为已定义符号。
- 说明：早前按 `0xb008` 解析出的 `316` 条表是一张较小的影子表，不是 linker 使用的主符号表；以本节为准。
- 覆盖率：`274/316` 条名字可完整解析（其余因名称拼接/加密留空）。
- 导出函数 `297` 条，关键项：

| 地址 | 大小 | 名称 |
|---|---|---|
| `0x2e6c0` | 0xac | `prepare_vmdex` |
| `0x2e820` | 0xe4 | `DexFileLoader::Load`（分派） |
| `0x2ea54` | 0x160 | `DexFileLoader::LoadV28` |
| `0x2ed50` | — | `LoadV34_BETA1` / `0x2ef18 LoadV34_DP2` |
| `0x2f628` | 0x1c8 | `so_postfix_wrap`（RC4） |
| `0x2f7f0` | 0x206c | `JNI_OnLoad` |
| `0xa1108` | 0 | `nop_arm64_v8a_beg`（标记符号） |
| `0xa110c` | 0 | `fault_arm64_v8a_ldxr_beg`（标记符号） |
| `0xef1a0` | 0x18 | `multidex_entry`（RW 别名） |
| `0xef1b8` | 0x8 | `v1jar_mapaddr` |
| `0xef1c0` | 0x2008 | `file_queue`（inotify 队列） |
| `0xf11c8` | 4 | `queue_head` |
| `0xf4040` | 8 | `tree_filename` |

- 组件符号（证实静态链接）：
  - libelf/elfutils：`elf__load/unload`、`parse_elf_header_32_be`、`elf_rva_to_offset_64_le`、`hex_yy*`
  - inotify-tools：`inotifytools_watch_recursively_with_exclude`、`rblookup`、`wildmatch`、`add_exclude`
  - 字符串/工具：`ss_new`、`ss_istartswith`、`strlcat`、`memmem`、`xtoi`、`get_hash`
  - C++ ABI：`__cxa_*`、`_ZTI/_ZTV/_ZTS` 大量条目
- `nop`（`0x2f24c`，4 字节）与 `nop_arm64_v8a_beg` / `fault_arm64_v8a_ldxr_beg` 是**给运行时 patch 用的定位标记**：壳可在运行时按标记把指令改成 NOP，或在 LDXR 处注入故障处理。**[推断]**

### 11.3 与 libdexjni.so 的分工 **[观测 + 推断]**

- `libdexjni.so`（2.4 MB）的 `.dynamic` 同样只剩 `NEEDED`/`SONAME`，依赖 `libstdc++.so`，说明它使用同一套保护。
- `libDexHelper.so` 导出了完整的 C++ API（`DexFileLoader`、`safejni::*`、`Utils::*`），而 `libdexjni.so` 是 JNI 侧的调用方。**[推断]**
- 因此"还原全部功能"需要两个 `.so` 一起看：`libDexHelper` 提供保护运行时与加载器，`libdexjni` 负责 Java 侧入口与参数编排。**[推断]**

### 11.4 更新后的未解项

1. `sub_1088F0`/`sub_108914` 的解压算法与密钥派生（当前只见"区间解码 + 4 字节 XOR"）。
2. maps 自检标记的完整三段常量的语义（`__b_a_n_g_` / `c_l_e__che` / `word_108B3E`）。
3. `multidex_entry` / `v1jar_mapaddr` 数据别名的读取方（RW 侧谁在用）。
4. `JNI_OnLoad` 后半段（`0x2f7f0 + 0x1000` 之后）的线程创建与检测启动顺序。
5. `file_queue` / `queue_head` 监控的具体路径集合。

---

## 12. v0.3 更正与补全（2026-11-11 三次分析）

### 12.1 关键更正：dynamic 表是「双份」，不是被抹掉 **[观测]**

`PT_DYNAMIC` 里：

| 字段 | 值 | 指向 |
|---|---|---|
| `p_offset` | `0xeeb90` | 诱饵表：只有 6×NEEDED + SONAME |
| `p_vaddr` | `0xe8750` | 真表（文件 `0xe7750`）：INIT / INIT_ARRAY / SYMTAB / STRTAB / RELA / JMPREL / GNU_HASH |

Android linker 用 `p_vaddr` 计算内存位置，因此加载正常；按 `p_offset` 读文件的静态工具会被骗。此前的「动态表被抹除」结论作废。

### 12.2 真符号表（1508 条）中的核心入口 **[观测]**

| 地址 | 大小 | 符号 | 作用 |
|---|---|---|---|
| `0x108098` | 0xdc | `DT_INIT` | 自解密引导（maps 自检 → mmap RWX → 解密 → icache → mprotect → 迁移） |
| `0x2d230` | 0x22c | `DT_INIT_ARRAY[0]` / `start` | C++ 全局构造（连续 `sub_2D1D0`/`sub_2C870`） |
| `0x2f7f0` | 0x206c | `JNI_OnLoad` | 注册 `com.secneo.apkwrapper.H` 的 3 个 native、解密配置、启动检测 |
| `0x2e048` | 0x2d0 | `load(int, void*, const char*, size_t)` | ART 21/22 路径的内存 DEX 加载 |
| `0x2e3c4` | 0x124 | `load23(void*, const char*, size_t)` | ART 23 路径 |
| `0x2dfec` | 0x44 | `transfer(char*, char)` | 字节→十六进制字符转换（非 DEX 搬运） |
| `0x2e6c0` | 0xac | `prepare_vmdex(int)` | VM 侧准备 |
| `0x2e820` | 0xe4 | `DexFileLoader::Load` | 按 SDK 分派 |
| `0x2e904/0x2ea54/0x2ed50/0x2ef18` | — | `LoadV26/V28/V34_BETA1/V34_DP2` | 各版本 ART 加载 |
| `0x2f42c` | 0x1fc | `so_prefix_wrap(void*, int)` | 解密前处理（与 postfix 成对） |
| `0x2f628` | 0x1c8 | `so_postfix_wrap(void*, int)` | RC4 KSA + XOR 解密 |
| `0x2f1a4` | 0xa8 | `handle_exception_sig(int, int)` | 信号/异常处理 |
| `0x2d498` | 0x118 | `scan_gettimeofday(void*)` | 时间检测（反调试/反加速） |
| `0x9d294` | 0x20 | `sha256_init` | 哈希（完整性校验候选） |
| `0xef1a0` | 0x18 | `multidex_entry` | multidex 入口（RW 段） |
| `0xef1b8` | 0x8 | `v1jar_mapaddr` | v1 jar 映射地址（RW 段） |
| `0xf13bc` | 0xc | `g_sym_JNI_OnLoad` | 保存解析出的 JNI_OnLoad 指针 |

JNI/工具层符号（完整列表见 `dynsym_real.json`）：`safejni::invoke/invokeStatic/AllocObjectAPI/NewObjectAPI/setObjectFieldAPI/getStaticFieldAPI`、`Utils::getMethodInfo/getStaticMethodInfo/toJString/dumpReferenceTable/checkException`、`addLocalRef/deleteLocalRef`（按数组类型 10 余个重载）、`JNIException`、`base64_decode`、`lookup(JNINativeMethod*)`、`api_version`、`throwJavaExcpetion`、`catchMethod`。

静态链接组件：libelf（`elf__load` 0xa0600/0x874、`parse_elf_header_*`、`elf_rva_to_offset_*`、`hex_yy*`）、inotify-tools（`inotifytools_*`、`rbinit/rblookup`、`wildmatch/add_exclude`）、字符串工具（`ss_*`、`strlcat`、`memmem`、`xtoi`、`get_hash`）、sha256。

### 12.3 加载总链（修正版） **[观测 + 推断]**

```
ART/Java: AW.attachBaseContext → H.load() → System.loadLibrary("DexHelper")
   └─ linker: map 3 segments → 按真 .dynamic 重定位
        → DT_INIT(0x108098)  自解密首段（maps 自检失败即 exit_group）
        → DT_INIT_ARRAY(0x2d230)  C++ 静态构造
        → dlsym("JNI_OnLoad") → 0x2f7f0
             ├─ RegisterNatives(com/secneo/apkwrapper/H): gha/sha/he 三个方法
             ├─ 解密全局配置（qword_F13F8 等）
             ├─ DexFileLoader / load / load23 / transfer / prepare_vmdex → 内存 DEX
             └─ 启动检测线程（0x50248 / 0x51024 / 0x4B4F0 / 0x2DBC0 等）
```

### 12.4 仍未解决

1. **首段解密算法细节**：`sub_1085EC` 里 `sub_1088F0 → sub_108914` 是位流 LZSS 变体（非 LZMA；字面量/长度/距离编码已读出），但密钥来源与压缩块头仍需逐字段确认。
2. **RW 段的 `multidex_entry`/`v1jar_mapaddr`**：这两个符号位于 `PT_LOAD#2` 的 `memsz` 超出 `filesz` 的区域（文件无字节，运行时为零/由壳写入）；谁在使用、是否运行时生成代码，未证实。
3. **maps 自检标记三段常量**（`__b_a_n_g_` / `c_l_e__che` / `word_108B3E`）的完整语义。
4. **JNI_OnLoad 后半段**（0x2f7f0 + 0x1000 之后）的线程与检测启动顺序。
5. **完整性校验**（`sha256_init`、`manifest.mf`/`rsa.sig`）的调用点。

---

## 13. v0.4：JNI_OnLoad 全貌与 ART 篡改（2026-11-11 四次分析）

### 13.1 JNI_OnLoad（0x2f7f0）的执行顺序 **[观测]**

1. `GetEnv(JNI_VERSION_1_4)`。
2. `FindClass("com/secneo/apkwrapper/H")` → `RegisterNatives(H, table, 3)`（`gha(String)I`、`sha(String,I)V`、`he(I)V`）。
3. 解密并填充全局结构 `qword_F13F8`（类名 H/AW、`com/a/b/d/BD`、`arm64`、PKGNAME 字段清空等）。
4. **SDK / ART 检测**：
   - 读版本号并按 `LOWORD` 与 `'N'(78) 'O'(79) 'P'(80) 'Q'(81) 'R'(82) 'S'(83)` 比较，得到 ART 版本号（23/25/27/28/29/30/31…）。
   - SDK ≥ 31 时用 `PackageManager.MATCH_APEX` 查 `com.google.android.art` / `com.android.art`，再从 `PackageInfo.getLongVersionCode()` 计算 ART 版本（≥101 时循环除以 10）。
   - 结果写入 `qword_F13F8+0`（SDK）、`+4`、`+16`、`+20`（versionCode）。
5. **模块基址解析**：
   - `sub_39338("libart.so")` → `qword_F13F8+32`
   - `sub_39338("libdexfile.so")` → `qword_F13F8+40`
6. **路径构造**（重叠 4 字节写入拼串）：`oat`（+376）、`.cache`（+392）等，随后 `"%s/%s/%s"` → `<cache>/oat/arm64`，并派生：
   - `classes.jar`（+408）、`classes.dex`（+472）、`classes.odex`（+536）
   - `"envc.push"` 探针路径
7. **动态补注册 3 个 native**（`JNIEnv+1720 = RegisterNatives`）：
   - `AW.hn(Landroid/content/Context;Landroid/app/Application;)V` → `loc_39FB4`
   - `AW.pn()V` → `sub_3B05C`
   - `H.d(Ljava/lang/String;)Ljava/lang/String;` → `unk_3BDD4`
8. `sub_3185C(env)` —— 壳主初始化（见 13.2）。
9. 首次调用时把 `"JNI_OnLoad"` 写入全局槽并清零一段结构（`g_sym_JNI_OnLoad` 相关，`qword_F13BC` 符号）。

### 13.2 壳主初始化 `sub_3185C` 与 ART 篡改 **[观测]**

`sub_3185C`（22,564 B）内部通过 `sub_390E8` 解析 ART 符号。`sub_390E8` 是**自实现的 ELF 动态符号解析器**（解析自身/目标模块的 program header → PT_DYNAMIC → DT_SYMTAB/STRTAB 查找），不走系统 `dlsym`，可绕过 linker Hook。

实测解析/调用的 ART 符号（字符串位于 `0xc5xxx`）：

| 目标 | 符号 | 用途（推断） |
|---|---|---|
| `/lib64/libart.so` | — | 通过 `sub_47568` 打开 libart |
| `_ZN3art8verifier14MethodVerifier11VerifyClassEPNS_6mirror5ClassEbPNSt3__112basic_string...` | `verifier::MethodVerifier::VerifyClass` | 关闭/绕过 DEX 校验 |
| `_ZN3art7Runtime9instance_E` | `art::Runtime::instance_` | 取得 Runtime 单例 |
| `_ZNK3art7Runtime21IsVerificationEnabledEv` | `Runtime::IsVerificationEnabled` | 读/改校验开关 |

结论：**壳在加载 DEX 前先篡改 ART 的校验路径**（至少包括 `VerifyClass`、`Runtime::instance_`、`IsVerificationEnabled`），这是"加密 DEX 可直接进内存加载"的前提。

### 13.3 修正

- `transfer`（`0x2dfec`）不是 DEX 搬运，而是**字节转十六进制字符**（`0x2e048` 的 `load` 用的是别的路径）。
- `sub_3185C` 是 JNI_OnLoad 唯一的直接子调用（`0x31138`），即壳真正的"启动器"。
- `create_thread`（`0x2f188`）、`load`（`0x2e048`）、`load23`（`0x2e3c4`）在本 `.so` 内**没有直接 BL 调用点**：它们是通过符号表导出、由 `libdexjni.so`（JNI 桥）按需调用的 API。**[观测 + 推断]**

### 13.4 下一步

1. 读 `sub_3185C` 中的 DEX 加载分支（哪些地址最终调用 `DexFileLoader::LoadV*` / `load` / `load23`）。
2. 确认 `sub_47568`（打开 `/lib64/libart.so`）与 `VerifyClass` 的具体篡改手法。
3. 还原 `classes.dex`/`classes.odex` 缓存路径的实际写入者（可能是 `libdexjni`）。

---

## 14. v0.5：导入桩还原（可读性关键突破）

### 14.1 问题

IDA 只看到了诱饵 dynamic（`p_offset`），因此把 PLT 导入桩全部标成 `sub_2Bxxx` / `sub_2Cxxx`，导致 `JNI_OnLoad`、`sub_3185C` 的伪代码充满不可读的间接调用。

### 14.2 解法 **[观测]**

用真 dynamic 的 `DT_SYMTAB=0x5290` + `DT_STRTAB=0xdff0` + `DT_RELA=0x1d6d8` / `DT_JMPREL=0x27590` 建立 `r_offset → 符号名` 映射；再扫描桩模板：

```
adrp x16, page
ldr  x17, [x16, #imm]
add  x16, x16, #imm
br   x17
```

`page+imm` 即 GOT 地址（`0xe8xxx/0xe9xxx`），查表得到导入名。

### 14.3 已还原的导入桩（示例）**[观测]**

| 桩地址 | GOT | 导入符号 |
|---|---|---|
| `0x2BB10` | `0xe9088` | `access` |
| `0x2B000` | `0xe8b00` | `open` |
| `0x2BA40` | `0xe9020` | `write` |
| `0x2CB70` | `0xe98b8` | `close` |
| `0x2C9F0` | `0xe97f8` | `strstr` |
| `0x2BE60` | `0xe9230` | `fgets` |
| `0x2B940` | `0xe8fa0` | `sscanf` |
| `0x2BCE0` | `0xe9170` | `fclose` |
| `0x2CEC0` | `0xe9a60` | `fopen` |
| `0x2D0E0` | `0xe9b70` | `__system_property_get` |
| `0x2BC70` | `0xe9138` | `memcmp` |
| `0x2BE50` | `0xe9228` | `__stack_chk_fail` |

### 14.4 由此可直读的关键逻辑

- `sub_1082A8`：`fopen("/proc/self/maps")` → `fgets` 逐行 → `strstr(line, magic)` → `fclose`；未命中即 `exit_group(94)`。
- `JNI_OnLoad` 的版本检测：`__system_property_get("ro.build.version.sdk")` → `sscanf`；APEX 分支查 `com.google.android.art`。
- `sub_39338`：同样用 `fopen("/proc/self/maps")` + `strstr` + `sscanf` 找 `libart.so`/`libdexfile.so` 的基址。
- `sub_3185C` 内的 `access`/`open` 组合用于探测 `/lib64/libart.so` 等路径。

### 14.5 工具

- `analysis/tools/rename_imports.py`：解析真 dynamic + 重定位 → 输出 `import_stubs.json`，并生成把 `sub_XXXX` 替换成真实导入名的伪代码副本 `analysis/libDexHelper/renamed/`。

### 14.6 下一步

1. 用重命名后的伪代码重读 `JNI_OnLoad` 与 `sub_3185C`，把 `__system_property_get` 的属性名全部列出。
2. 还原 `sub_47568`（打开 `/lib64/libart.so`）与 `VerifyClass` 篡改的具体指令级手法。
3. 用 `renamed/` 版本重画检测与 DEX 加载数据流。

---

## 15. v0.6：导入桩重命名 + 关键字符串（2026-11-11）

### 15.1 工具与产物

- 修正 ADRP/LDR 解码（imm12 按 8 缩放）后，`analysis/tools/rename_imports.py` 扫描 593 个桩，**解析出 250 个导入名**，写出 `import_stubs.json`，并生成 827 个重命名伪代码文件到 `analysis/libDexHelper/renamed/`。
- `analysis/tools/ida_retype_dump.py`：对 25 个常用 libc 导入应用函数原型并重命名，再重新反编译 `JNI_OnLoad` 与 `sub_3185C`，输出到 `analysis/libDexHelper/retyped/`（IDA 自动加 `_0` 后缀）。

### 15.2 JNI_OnLoad 读取的系统属性 **[观测]**

```
ro.build.version.sdk
ro.build.version.release
ro.build.version.codename
ro.product.cpu.abi
ro.product.manufacturer
persist.sys.dalvik.vm.lib
persist.sys.dalvik.vm.lib.2
ro.yunos.version
ro.yunos.version.release        ← YunOS 检测
```

版本判定逻辑：`codename` 首字符与 `'N'~'S'` 比较；`sdk`/`release` 联合定 ART 版本；`persist.sys.dalvik.vm.lib*` 判断 Dalvik/ART。

### 15.3 `sub_3185C` 的实际行为（retyped 版本）**[观测]**

- `SDK < 28`：`snprintf("/proc/%d/maps")` → `fopen` → `fgets(1024)` 逐行 → `strstr(line, needle)` → 校验不含 `.cache` 路径 → `sscanf` 取模块基址。**[观测]**
- `SDK ≥ 28`：构造 oat/odex 路径 `"/%s/%s/%s"`（`"oat"` + `arch` + 模块文件名，来自 `qword_F13F8+608` 的 `strrchr('/')`）+ `"odex"`。
- 还有：`fopen("/proc/self/cmdline")`、`access(path, 0)` 预检、多组 `fopen(path, "r")` 读取。

### 15.4 结论

`sub_3185C` = **模块定位 + oat 路径推导 + ART 符号解析 + 校验开关篡改** 的总入口；`JNI_OnLoad` 只负责 JNI 注册与配置准备。DEX 的实际加载调用（`load/load23/DexFileLoader::Load*`）由 `libdexjni.so` 通过导出的 C++ 符号触发。**[观测 + 推断]**

### 15.5 下一步

1. 用 `retyped` 思路批量重反编译 `sub_3185C` 调用的子函数，补全 `VerifyClass` 篡改细节。
2. 把 `sub_1085EC` 的区间解码器与 XOR 逻辑反写成可运行 Python，验证能否从静态文件还原本地 `dec.so`（等价性验证）。
3. 按 `libdexjni.so` 的导入表确认它调用了哪些 `libDexHelper` 导出。

---

## 16. v0.7：自解密算法完整还原并验证（等价性达成）

### 16.1 引导描述符（`0x108B48`）**[观测]**

`DT_INIT` 的汇编：

```
x1 = 0x108078
x0 = qword[0x108078] + x1      ; = 0xad0 + 0x108078 = 0x108B48  (描述符)
x3 = x1 - qword[0x108088]      ; = 0
x1 = x3 + qword[0x108090]      ; = 0x2AD10  (压缩数据起点)
bl sub_1087DC                  ; mmap(RWX) + memcpy(0x2AD10, len=0x53EDE)
bl sub_10850C(0x108B48, 0x2AD10, newbuf)
```

描述符（u32 字段）：

| 偏移 | 值 | 含义 |
|---|---|---|
| `+0x00` | `0x2D230` | `DT_INIT_ARRAY` 目标 |
| `+0x04` | 1 | — |
| `+0x08` | `0x549DB` | — |
| `+0x0C` | `0x2AD10` | 压缩数据起点（= 解压输出起点） |
| `+0x10` | `0xEE0C8` | 重定位表 A |
| `+0x14` | 0 | 重定位计数 |
| `+0x18` | `0xEE0C8` | 重定位表 B |
| `+0x1C` | `0xB8B00` | **解压后长度**（`0x2AD10+0xB8B00 = 0xE3810`，正好首段末尾） |
| `+0x20` | 0 | XOR 长度（本样本为 0） |
| `+0x24` | `0x2AD10` | — |
| `+0x28` | `0x53EDE` | **压缩数据长度** |

### 16.2 解压算法（`sub_108914`）**[观测]**

位流 LZSS：

- 位读取：MSB 优先；缓冲区 `w4` 低 7 位为 0 时从输入取 1 字节并置 `w4 = (byte<<1)|1`；取位 `(w4>>8)&1`。
- 字面量段：位=1 时取 1 字节输出；位=0 结束。
- 长度类：`w6=1`；循环 `w6=(w6<<1)+b1`；若 `b2==0` 则 `w6=((w6+0x7fffffff)<<1)+b3` 继续，`b2==1` 结束。
- 距离/结束：
  - `w6==2` 时：距离沿用上一条；
  - 否则 `w5 = in[i] + (w6<<8) - 0x300`，`i++`；`w5==0xffffffff` 为**结束标记**；否则 `dist = (w5>>1)+1`。
- 尾部长度：`w6 = (w6<<1)+b`；若为 0，则走 `w6=1; loop w6=(w6<<1)+b1; until b2==1; w6+=2`。
- 拷贝：先输出 1 字节，再从 `out_pos-dist+1` 起复制 `w6` 字节（允许重叠）；`dist > 0x500` 时长度再 +1。
- 返回值：消费输入长度必须等于 `a2`，否则返回 `-0xc9/-0xcd`。

### 16.3 等价性验证 **[观测]**

`analysis/tools/lzss_decode.py` 按上述语义实现，验证结果：

```
输入：libDexHelper.so[0x2AD10 : 0x2AD10+0x53EDE]
输出：0xB8B00 (756,480) 字节
与运行时 dump (dumps/dexhelper_mem.bin) 同区间比较：mismatch 0 / 756480
用解压结果替换静态文件首段后：
  libDexHelper.static-dec.so  SHA-256 = c37fabca988ae1bb7d547de375c705b4f2aa77dace967e1a7de8775e870c6523
  libDexHelper.dec.so         SHA-256 = 同上
```

即：**现在仅凭 APK 内的静态 `.so`，无需设备即可完整还原解密镜像，且与运行时 dump 字节完全一致。**

### 16.4 意义

- 后续所有静态分析都可基于 `libDexHelper.static-dec.so`，可复现、可审计。
- 也说明运行时 dump 没有丢失/改动首段，此前基于 dump 的结论（检测点、伪代码）全部有效。
- 对"等价还原"目标，**自解密层已经可等价重放**；剩余工作量集中在功能层（DEX 加载、检测、ART 篡改）。

### 16.5 下一步

1. 把 `sub_1083AC` 的重定位应用（`+0xEE0C8`, count=0）也写进 Python 流水线，形成 `unpack.py` 一键还原。
2. 用 `static-dec.so` 重跑 IDA 分析，确认与 `dec.so` 的伪代码一致（应完全一致）。
3. 继续功能层：`VerifyClass` 篡改、DEX 解密数据流。

---

## 17. v0.8：改用开源 Unicorn 直接执行原解压函数

### 17.1 动机

手写移植虽然已验证，但维护成本高、换样本易出错。按"能直接用开源代码就不要自己重写"的原则，改为用开源 **Unicorn Engine** 直接模拟执行 `libDexHelper.so` 内的原始 `sub_108914`。

### 17.2 实现

`analysis/tools/unicorn_unpack.py`：

1. 解析 `libDexHelper.so` 的 3 个 `PT_LOAD`，按 `p_vaddr` 映射并写入文件内容。
2. 额外映射：压缩数据缓冲（`0x30000000`）、输出缓冲（`0x20000000`）、长度指针、栈。
3. 设参调用：
   ```
   x0 = 0x2AD10（压缩数据）  x1 = 0x53EDE（压缩长度）
   x2 = 输出缓冲            x3 = &outLen
   LR = 哨兵，emu_start(0x108914)
   ```
4. 读取 `outLen` 与输出，替换静态文件首段，写出 `libDexHelper.unicorn-dec.so`。

依赖：`pip install unicorn`（2.1.4）。

### 17.3 验证（第三种独立方法）

```
decompressed size = 0xB8B00 (756,480)
sha256(unicorn-dec.so) = c37fabca988ae1bb7d547de375c705b4f2aa77dace967e1a7de8775e870c6523
sha256(dec.so)         = c37fabca988ae1bb7d547de375c705b4f2aa77dace967e1a7de8775e870c6523
```

三种路径（运行时 dump、Python 移植、Unicorn 执行原码）结果完全一致。

### 17.4 结论与取舍

| 方式 | 优点 | 适用 |
|---|---|---|
| Unicorn 执行原函数 | 零移植误差；换版本只需改地址/描述符 | **推荐**，可复现 |
| Python 移植 `lzss_decode.py` | 无额外依赖、可读、可嵌进纯 Python 工具链 | 参考实现/交叉验证 |

上游也有同类工作可对照：`Evarentha/secneo-static-unpacker-20261108`（不同样本、同族算法，采用 Unicorn 模拟 `sub_AFBF0` 的思路一致）。

### 17.5 下一步

1. 把 Unicorn 步骤参数化（从描述符 `0x108B48` 读取 `src/len/outlen/xor/reloc`），做成通用 `unpack.py`，可直接处理其它 SecNeo 变体。
2. 在 Unicorn 中继续模拟 `sub_1085EC` 全链（含 maps 自检、mprotect、reloc），实现"完整 DT_INIT 重放"。
3. 功能层：`VerifyClass` 篡改与 DEX 解密数据流。

---

## 18. v0.9：通用 `unpack.py`（Unicorn 全链重放）

### 18.1 设计

`analysis/tools/unpack.py` 不再依赖对本样本的任何硬编码，流程全部从 ELF 自身推导：

1. 解析 `PT_LOAD`（按 `p_vaddr` 映射并写入文件内容）。
2. 读**真** `PT_DYNAMIC`（`p_vaddr`，不是 `p_offset`），取 `DT_INIT`；若无则取 `DT_INIT_ARRAY` 条目。
3. 全镜像扫描 `mov x8,#nr; svc #0; ret` 桩，建立 `地址 → 系统调用号` 表，并用 Unicorn code hook 实现：
   - `mmap(222)`：在模拟地址空间分配；
   - `mprotect(226)` / `munmap(215)`：直接成功；
   - `openat(56)`：`/proc/self/maps` 返回合成内容（含从二进制中自动提取的 SecNeo 标记）；
   - `read(63)` / `write(64)` / `close(57)`；
   - `exit_group(94)`：停止并告警。
4. 设置 `TPIDR_EL0`（栈保护 canary）、栈、LR 哨兵，直接 `emu_start(DT_INIT)`。
5. 模拟结束后，把每个 file-backed `PT_LOAD` 的当前内存内容写回文件。

**原函数（自检、解压、mprotect、重定位、icache flush）全部原样执行**，没有重写任何算法。

### 18.2 本样本结果 **[观测]**

```
unpack.py analysis/libDexHelper/libDexHelper.so -o libDexHelper.unpacked.so \
          --verify dumps/dexhelper_mem.bin
PT_LOADs: [(0x0, R-X), (0xe5270, RW-), (0x108078, R-X)]
DT_INIT: 0x108098
wrote 979501 bytes sha256=c37fabca988ae1bb7d547de375c705b4f2aa77dace967e1a7de8775e870c6523
verify vs dumps/dexhelper_mem.bin: 0/931856 bytes differ
```

与三种既有还原结果（dump / Python LZSS / Unicorn 单函数）的 SHA-256 完全一致。

### 18.3 通用性验证：`libdexjni.so` **[观测]**

同一脚本直接处理第二个受保护库，无任何参数修改：

```
PT_LOADs: [(0x0, R-X), (0x98a10, RW-), (0x283078, R-X)]
DT_INIT: 0x283098
syscall stubs: 0x283174/0x283180/0x283194/... （与本样本完全同构）
wrote libdexjni.unpacked.so (2,568,669 B) sha256=6afd3914857d185d0b26ab1a5a555563c228af909dccfd2481dfa6fc52f217f9
```

有效性检查：静态文件在 `0x10000` 处无法反汇编（0/64 条），解包后 **64/64 条全部可解为合法 ARM64**。说明同族变体可直接复用。

### 18.4 通用性说明

- 没有任何本样本常量：入口来自 dynamic，系统调用号来自桩扫描，标记来自二进制搜索。
- 对 SecNeo 同族变体（不同压缩长度、不同偏移、额外 XOR 或 `DT_INIT_ARRAY` 初始化）预期可直接工作；若某变体使用不同 syscall 集合，仅在 `_syscall` 中补充对应号即可。
- 无 `DT_INIT` 的普通库会明确报错，不会误改文件。

### 18.5 依赖

```
pip install unicorn   # 2.1.4
```

### 18.6 下一步

1. 用 `libDexHelper-x86.so` / `libSdkHelper_core.so` 验证更多变体与失败模式（`libdexjni.so` 已通过）。
2. 在 Unicorn 上继续模拟 `DT_INIT_ARRAY`（`0x2d230`）与 `JNI_OnLoad`，观察 `VerifyClass` 篡改的实际写操作。
3. 功能层：DEX 解密数据流与 `OpenCommon` hook。

---

## 19. v1.0：多 so 验证矩阵（2026-11-11）

### 19.1 结果

| 库 | 架构 | 结果 | 说明 |
|---|---|---|---|
| `libDexHelper.so` | AArch64 | ✅ 成功 | `sha256=c37fabca…6523`，与运行时 dump 0/931856 字节差 |
| `libdexjni.so` | AArch64 | ✅ 成功 | `sha256=6afd3914…17f9`；解包后 `0x10000` 处 64/64 条合法 ARM64 |
| `libSdkHelper_core.so` | AArch64 | ✅ 无壳可解 | 真 dynamic 无 `DT_INIT`、`INIT_ARRAY[0]=0`；脚本明确提示 `nothing to unpack`，文件不变 |
| `libDexHelper-x86.so` | x86-64 | ❌ 暂不支持 | `DT_INIT=0x131098` 进入后模拟在 CFF 分派器处发散（`UC_ERR_EXCEPTION @0x2456`），镜像不变；脚本报 `emulation failed` |

### 19.2 x86-64 变体分析

- 结构镜像 arm64：`DT_INIT` 自带描述符解算（`desc @0x1318AF`、压缩源 `0x2B908`），并调用 `sub_1315AD`（mmap+拷贝）与 `sub_1313D8`（解压/迁移）。
- 但 x86-64 版本的两个函数开头是同一套 **CFF 状态机分派器**（`0x111/0x46/0x105/0x15`），模拟进入后控制流跳到 ELF 头附近再落到 `int3`，说明分派器依赖的某个运行时值（未重定位指针或栈布局）与我们的模拟环境不一致。
- 结论：x86-64 分支需要单独处理（或该库只用于 x86 设备，arm64 设备上不加载）。**[观测 + 推断]**

### 19.3 工具行为

`unpack.py` 现在会：

- 无 `DT_INIT`/`INIT_ARRAY` → 打印 `nothing to unpack`，输出与输入一致；
- 模拟异常且镜像未变化 → 打印 `emulation failed … not supported yet` 并以状态码 2 退出，避免把"未解包"误当成成功。

### 19.4 下一步

1. 若要覆盖 x86-64：在 Unicorn 中追踪 CFF 分派器的跳转表来源（对比 arm64 的等价实现），补齐 x86 专用栈/重定位环境。
2. 回归：把三个 arm64 库纳入一键脚本 `unpack-all.sh` 并记录哈希基线。
3. 回到主线的功能层：`VerifyClass` 篡改与 DEX 解密数据流。

---

## 20. v1.1：VerifyClass 篡改与 DEX 解密链路（2026-11-11）

### 20.1 VerifyClass 篡改（已还原）**[观测]**

**Hook 引擎**：`sub_A45DC`（符号名 `pS_5S5ISlS…`，2024 B）

- 若 `*(u32*)target == 0x58000050`（已 hook），只把 `*(u64*)(target+8)` 换成新回调（幂等重定向）；
- 否则写入 16 字节桩：`ldr x16, #8`（0x58000050）+ `br x16`（0xD61F0200）+ 回调地址。

**VerifyClass 被替换为恒假**：

```
dlsym(libart, "…MethodVerifier11VerifyClass…")  → 0x390E8
hook(target, 0x592A8, ctx)
0x592A8 = e0 03 1f 2a  c0 03 5f d6   →   mov w0, wzr ; ret
```

即 `MethodVerifier::VerifyClass(...)` 被改成永远返回 `0`。

**Runtime 字段被直接清零**：

1. 通过 `/lib64/libart.so` + 自定义 ELF 解析 `sub_390E8` 取 `art::Runtime::instance_`（`0xc5231`）与 `Runtime::IsVerificationEnabled`（`0xc524c`）。
2. 用 `sub_52CAC`（maps 解析）定位目标函数的映射区间，`mprotect(..., 7)`（`0x2ADE0`）。
3. 读取目标函数第一条指令的 `imm12`（`ubfx` 10..21）作为 Runtime 结构体偏移，校验落在 `0x301..0x4FF`。
4. 若 `Runtime+offset+0x20` 的值等于 `*(global+0x144)`，把 `Runtime+offset` 的字节清零（`0x357B0: strb wzr, [x8]`）。

结论：**"绕过验证"是组合手段**——函数级 hook（恒假）+ 结构体级标志清零。

### 20.2 DEX 加密/解密链路 **[观测 + 部分推断]**

**已确认的输入**：

| 文件 | 大小 | 特征 |
|---|---|---|
| `assets/coreclasses.bangcle` | 307,990 B | 熵 **8.0**，加密/压缩的核心 DEX |
| APK `classes.dex` | 134,024,136 B | 明文多 DEX 容器（7 处 `dex\n`，熵 6.37） |

**路径与文件处理（libDexHelper）**：

```
<data>/<pkg>/.cache/.../classes.dve      ← 加密 DEX 落盘名（"classes.dve"）
/data/user/0/<pkg>/  /data/user/1/<pkg>/ /data/data/<pkg>/
assets/RES_RULE                          ← 资源加密规则（11 字节记录，"KEY_RES_ENC"）
"enc_type/%d"                            ← 按 dword_F1630 选择加密类型
"<name>.edata" / "%s.bak"                ← 加密数据文件与备份
```

**加载器（libSdkHelper_core.so）**：

- 字符串 `assets/%sclass%s.bangcle`（即 `assets/coreclasses.bangcle`）。
- 导入：`inflate/inflateInit2_/inflateEnd`、`crc32`、`dlopen/dlsym`、`ptrace`、`inotify_*`、`arc4?`（无）。
- 控制流被 CFF 分派器混淆（`ldrh [table+idx*2]` + `adr` + `br`），字符串引用落在分派块内，普通 xref 看不到。

**已排除的方案**（对 `coreclasses.bangcle` 实测）：

- `zlib/gzip/raw deflate` 解压：全部失败；
- RC4（密钥候选：`<redacted-key-candidate>`、`46EBA22EF5204DD5`、包名、`TheApp`、Bangcle 标记、`KEY_RES_ENC` 等）：首块均非 `dex\n`；
- 单字节 XOR：无命中；
- AES-ECB/CBC（同批密钥）：首块均非 `dex\n`；
- 各库中均**不存在**标准 AES S-box（`libphofo` 的 AES 是 Java 侧 `AES/ECB/PKCS5/7Padding`）。

**推断**：核心 DEX 使用梆梆自研流密码/变体分组密码，密钥很可能由签名/manifest 派生（`assets/meta-data/manifest.mf`+`rsa.sig`），而不是硬编码常量。

### 20.3 下一步

1. **动态**：在加载 `libSdkHelper_core` 的进程（`:core` 或启动早期）注入，Hook `inflate` 返回点与引擎解密函数入口，直接抓明文 DEX；用现有 `bypass_final.js` 单会话组合。
2. **静态**：对 `libSdkHelper_core` 的 CFF 分派器做 devirtualization（跳转表 → 基本块图），定位 `coreclasses.bangcle` 解密函数。
3. 校验 `assets/meta-data/manifest.mf` + `rsa.sig` 与密钥派生关系。

---

## 21. 动态抓取 DEX 解密（2026-11-11 实测）

### 21.1 环境与方法

- 设备：`<device-serial>`，`frida-server-17.16.4 @ 127.0.0.1:49157`
- 注入：`frida -f com.example.reference`，单会话加载 `bypass_final.js` + `det_patch.js` + `msa_loop_off.js` + 抓取脚本
- 两种抓取方式：
  1. **ART 边界 Hook**：`libdexfile.so` 的 `DexFile::OpenCommon` / `ArtDexFileLoader::Open`，`onEnter` 拷贝缓冲、`setImmediate` 落盘（避免阻塞 ART）
  2. **内存扫描**：t=8s 扫描 `r--` 范围 `64 65 78 0a 30 33`（`dex\n03`），按 DEX 头 `file_size` 转储

### 21.2 主进程模块与文件访问（实测）**[观测]**

已加载：`libDexHelper.so`、`libdexjni.so`、`libphofo.so`、`libmsaoaidsec.so`；**`libSdkHelper_core.so` 不在主进程**。

启动期文件访问（`open/openat` 追踪）：

```
/system/framework/oat/arm64/org.apache.http.legacy.vdex
<app>/oat/arm64/base.vdex
<app>/base.apk
<app>/oat/arm64/base.art
<app>/lib/arm64/libDexHelper.so
/data/user/0/com.example.reference/.cache/classes.dve     ← 24 字节
<app>/base.apk   (再次)
```

`classes.dve` 实际内容（24 B）：

```
ea ea d8 42 e3 5e 75 2b 59 03 28 7e a6 ad 3d dd 8c c3 e2 6a 00 00 00 00
```

→ 它是**元数据**，不是加密 DEX。已实测以其为 RC4/XOR/AES 密钥材料解 `coreclasses.bangcle`，均未命中。

### 21.3 ART Hook 结果

- `OpenCommon` 捕获到共享库 DEX：
  - `org.apache.http.legacy`：487,024 B（`dex\n039`）
  - CompactDex：24,560 B（`cdex001`）
- **不要 Hook `libDexHelper` 自身函数**：`Interceptor.attach(load/load23)` 触发壳的自校验，实测 SIGILL（libDexHelper+0x40124）。只 Hook 系统库可稳定。
- 应用自身的大 DEX 在脚本注入前已由 ART 加载完毕，`OpenCommon` 只看到后续共享库加载。

### 21.4 内存扫描结果 **[观测]**

t=8s 扫描得到 **42 个唯一 DEX**，其中 **21 个与 FART 产物 MD5 完全一致**，覆盖全部 14 个业务 DEX：

| 大小 | 状态 |
|---|---|
| 16,167,180 / 15,069,456 / 12,858,436 / 12,203,520 / 12,111,240 | FART 一致 |
| 12,063,284 / 10,793,400 / 10,061,776 / 9,600,380 / 9,546,628 | FART 一致 |
| 9,504,208 / 8,803,412 / 8,615,800 / 5,804,368 / 4,970,224 | FART 一致 |
| 4,314,184 / 3,013,160 / 2,761,900 / 1,941,504 / 659,492 / 487,024 | FART 一致 |

产物：`analysis/dexcap_dynamic/`（42 个 DEX + `index.json`）。

### 21.5 结论

- **动态抓取解密后 DEX 已跑通并交叉验证**：内存扫描结果与 FART 逐字节一致。
- 大 DEX 是**运行时明文**存在于内存（不是从磁盘明文加载），可由扫描直接获得。
- 尚未拿到 `assets/coreclasses.bangcle` 的**解密算法/密钥**；`classes.dve` 只是 24 字节元数据。

### 21.6 下一步

1. 在 `libdexjni.so` 中定位 `coreclasses.bangcle` 的解密函数（Hook `inflate` 返回点 → 栈回溯 → 找调用者）。
2. 尝试用 `classes.dve` 的字段解释（20B 数据 + 4B 0）作为偏移/长度/校验，而非密钥。
3. 若密钥与签名/manifest 相关，验证 `assets/meta-data/rsa.sig` 与 `manifest.mf` 的派生链。

---

## 22. 用 Stalker 定位 DEX 交接点（2026-11-11）

### 22.1 inflate / Asset 路径结论

- Hook `libz.so` 的 `inflate`：调用全部来自 `libopenjdk`（Java ZIP 层），**没有**来自 `libDexHelper`/`libdexjni` 的调用；说明壳的解密不走 zlib。
- Hook `libandroid.so` 的 `AAssetManager_open/read/getBuffer`：只看到应用资源（`.pag`），**没有 `coreclasses.bangcle`**；Java `AssetManager` 内部路径不经过 NDK 的 `AAsset*` 包装。
- Hook `dlsym`：`libDexHelper` 会 `dlsym("...DexFileLoader10OpenCommon...")`，但**返回 0**（失败），壳改用自实现的 ELF 解析器 `sub_390E8`。

### 22.2 Stalker call probe（关键）

`Interceptor.attach` 对 `libDexHelper` 的 `load/load23` 会触发自校验（SIGILL），改用 **`Stalker.follow(主线程 tid)` + `Stalker.addCallProbe`**，不在目标代码打 patch。

探针地址（模块基址 + 偏移）：`load 0x2e048`、`load23 0x2e3c4`、`DexFileLoader::Load 0x2e820`、`LoadV26 0x2e904`、`LoadV28 0x2ea54`。

实测 `DexFileLoader::Load` / `LoadV28` 被调用 13 次，寄存器快照：

```
a2 = 0xf6b10c  0xba3600  0xb8cd88  0x9987d0  0xc43444  0xb81234
     0xa4b1b8  0x589150  0x41d448  0x865454  0x837778  0xe5f110  0x1da000
a3 = 指向 dex 的缓冲（头 'dex\n038'）
```

对照业务 DEX 大小：`0xba3600`=12,203,520、`0xb8cd88`=12,111,240、`0x9987d0`=10,061,776 … 完全一致。

### 22.3 抓取结果

在调用点按 `file_size` 转储 `a3` 缓冲，得到 13 个业务 DEX（26 个文件 = Load + LoadV28 各一次），**全部与 FART MD5 一致**：

```
16,167,180 / 15,069,456 / 12,858,436 / 12,203,520 / 12,111,240
12,063,284 / 10,793,400 / 10,061,776 /  8,803,412 /  8,615,800
 5,804,368 /  4,314,184 /  1,941,504
```

索引：`analysis/dexcap_stalker_index.json`；设备目录 `/sdcard/Android/data/com.example.reference/files/dexcap/dex_*.bin`。

### 22.4 尚未完成

- 调用点回溯帧（`0x7c6e89xxxx`/`0x7c6ee4xxxx`）在模块列表中未命中，`Thread.backtrace` 在 Stalker 上下文里解析不可靠；尚未把调用者映射到 `libdexjni` 的具体函数。
- 下一步：用 `Stalker` transform + `putCallout` 读取调用时的 `x30`(LR) 与上下文，或用硬件断点/`DebugSymbol` 解析返回地址，定位"解密→调用 Load"的那一层。

---

## 23. 取返回地址定位解密函数的尝试与结论（2026-11-11）

### 23.1 已尝试

| 方法 | 结果 |
|---|---|
| `Thread.backtrace`（FUZZY/ACCURATE）在 Stalker call probe 回调内 | 返回地址**不在任何模块/内存区间**，不可信；部分运行把 `gum-js-loop` 打崩（SIGSEGV addr 0x2） |
| Stalker call 事件（`events:{call:true}` + `Stalker.parse`） | 事件管线正常（格式 `[call, from, to, depth]`），但**没有**目标调用的记录 |
| Stalker transform + `putCallout`，匹配 `bl` 立即数 / `blr` / `br` 目标 | 能抓到大量内部跳转（`br x17` 的 LR 已打印），但**没有**命中 `DexFileLoader::Load` |

### 23.2 可靠线索（非 Stalker）

Hook `dlsym`（普通 Interceptor，`Thread.backtrace(ACCURATE)` 正常）得到的调用链：

```
JNI_OnLoad+0x3113c  →  sub_3185C+0x364d8  →  (bl 0x2D0C0)  →  …  →  DexFileLoader::Load
```

静态核对：`0x364d4: bl 0x2D0C0`，而 `sub_2D0C0` 是 **CFF thunk**（`sub_2AD10` → `JUMPOUT`，走计算跳转）。

动态探测 `sub_2D0C0 / sub_2CF60 / sub_2D090`：调用参数含 `0x80/0x200` 长度、`/apex/...` 路径等，确认它们是 CFF 分派器的基本块，而不是独立业务函数。

### 23.3 结论

- 「解密→Load」的逻辑位于 **`sub_3185C` 内部的 CFF 分派链**（`0x2D0xx`/`0x2E7xx` 一组 thunk），不是单一可识别的库函数。
- 用常规 LR/backtrace 手段在 Stalker 下拿不到调用者；需要先**还原 CFF 分派器**。

### 23.4 下一步（明确）

1. 在 Stalker transform 中对 `libDexHelper` 范围内所有 `bl`（立即数）与 `blr/br` 记录 `(from, target, lr)` 到环形缓冲；在 `Load` 的 call probe 触发时打印最近 50 条，得到完整 CFF 路径。
2. 据路径中的 `br` 目标集合还原跳转表（`0x2A000–0x2F000` 区间），把分派块映射回源码级逻辑。
3. 找到真正处理 DEX 缓冲的块后，hook 其参数/返回值，抓「密文→明文」的算法。

---

## 24. 环形缓冲还原 CFF 路径（2026-11-11 结果）

### 24.1 实现

`Stalker.follow(主线程)` + transform 只对 `libDexHelper` 内的 **`bl` 立即数**（目标在模块内）记 `(from, target, lr)` 到 300 条环形缓冲；在 `DexFileLoader::Load` 的 call probe 触发时打印最近 40 条。该轻量版本稳定（重版含 `br/blr` 全量 callout 会拖慢/崩 `gum-js-loop`）。

### 24.2 命中路径 **[观测]**

```
#789188 bl +0x2eac8 -> +0x2c870   (lr+0x2eaac)
#789189 bl +0x2e33c -> +0x2cb30   (lr+0x2eacc)
#789190 bl +0x2e390 -> +0x2cdd0   (lr+0x2e340)
#789191 bl +0x364d4 -> +0x2d0c0   (lr+0x364d8)
=== HIT DexFileLoader::Load ===
```

即 `sub_3185C + 0x364d4` 调 `sub_2D0C0`，随后进入 `DexFileLoader::Load`。

### 24.3 CFF thunk 参数（call probe） **[观测]**

`sub_2D0C0` 每次调用的寄存器：

```
a0 = 0x7fdfb62970        (loader 上下文)
a1 = 0x7fdfb62578        (std::string 临时对象)
a2 = size                (0xf6b10c / 0xba3600 / 0xb8cd88 / 0x9987d0 … 业务 DEX 大小)
a3 = buffer              (0x7c4099fbc0 …，内容 'dex\n')
```

**结论：进入 `sub_2D0C0` 时缓冲已经是明文 DEX** → 解密发生在 `sub_3185C` 内部、`0x364d4` 之前，而不是 `sub_2D0C0` 里。

`sub_2C870/2CB30/2CDD0` 的参数均为长度 8 的字符串/对象（`a1=0x7c513a9f71`），是 std::string/vector 辅助，不是解密。

### 24.4 失败的一步

Hook `malloc/calloc/mmap/mmap64` 记录 ≥1MB 分配的调用栈，想直接拿到「分配并填充 DEX 缓冲」的函数；但该组合会让 `gum-js-loop` 崩溃（SIGSEGV addr 0x2），两次复现，放弃。

### 24.5 下一步

1. 静态读 `sub_3185C` 中 `0x363xx` 之前、生成 `(a2=size, a3=buffer)` 的代码段，定位写缓冲的调用（解密）。
2. 或对 `sub_3185C` 内每个 `bl` 目标逐个加 call probe，找第一个参数/返回值出现「大缓冲 + dex 魔数」的调用。

---

## 25. 逐个 call probe 结果：找到加密容器与原地解密位置（2026-11-11）

### 25.1 探针结果（sub_3185C 内 101 个 bl 目标）

高价值调用：

| 目标 | 参数 | 说明 |
|---|---|---|
| `+0x41f80` | `a0="com.example.reference"`、`a1="/data/ap..."` | 资源/edata 处理入口 |
| `+0x2d030` | `a0=PK\x01\x02…`、ELF 头、`/apex/...` | ZIP/ELF 缓冲处理 |
| `+0x2ccd0` | `a0=0x7c4c42a000 (7f454c46…)`、`a1=0xeed10`、`a2=0x10` | 处理 ELF 镜像（约 978 KB） |
| `+0x2c950` | `/proc/21…`、`/dev/null`、`/apex/…` | 字符串比较/过滤 |
| `+0x2d0c0` | `a2=size`、`a3=dex 缓冲` | 转交 `DexFileLoader::Load` |

**没有**任何一个直接 bl 目标收到 10 MB 级的 DEX 尺寸参数 → 解密不在这层。

### 25.2 关键发现：DEX 缓冲位于 `classes.jar` 的 rw 映射内 **[观测]**

对 `sub_2D0C0` 的 `a3` 做区间查询：

```
buf=0x7c3efaebc0 size=0xf6b10c head="dex\n"
   range base=0x7c3ef86000 size=134,025,216 prot=rw-
   file=/data/data/com.example.reference/.cache/classes.jar
buf=0x7c3ff1abc0 size=0xba3600 head="dex\n"
   range base=0x7c3ef86000 size=134,025,216 prot=rw-
   file=/data/data/com.example.reference/.cache/classes.jar
```

即：壳把 134 MB 的 `classes.jar`（头部是合法 `dex\n038`，正文加密）**mmap 成可写**，在内存里**原地解密**，再把各子区间交给 `DexFileLoader::Load`。

### 25.3 已取得密文/明文对

- 通过 Frida `File` 分块复制出 `/data/data/com.example.reference/.cache/classes.jar`（134,024,136 B，与 APK `classes.dex` 同尺寸、同头）
- 文件在偏移 `0x28BC0` 处为密文（`6a a8 d4 10 …`），同偏移内存中为明文 DEX（`dex\n038`）
- 计算 `keystream = pt XOR ct`：熵 7.61，周期检测（8/16/32/…/4096）命中率均 ≈ 0.004（随机水平）→ **流密码/CTR 类，非简单 XOR 重复密钥**

### 25.4 下一步

1. 用 `MemoryAccessMonitor` 监视 `classes.jar` 映射的首页，在解密写入发生时记录访问，然后立刻 `Stalker.follow` 该线程，抓写循环的 PC（或尝试硬件观察点）。
2. 收集全部 13 个 (ct, pt) 对（偏移 = `buf - 0x7c3ef86000`），对 RC4/AES-CTR/自研 PRNG 做判别。
3. 若能在 `libDexHelper` 中找到 RC4/PRNG 常量（S 盒、IV、种子），与其 `classes.dve`（24 B 元数据）关联。

---

## 26. MemoryAccessMonitor 抓写线程（2026-11-11 尝试）

### 26.1 结果

| 步骤 | 观测 |
|---|---|
| 轮询 `Process.enumerateRanges('rw-')` 找 `classes.jar` 映射 | **t≈536 ms** 出现，`base` 随机、`size=0x7FD1000`（134 MB） |
| 在 `base+0x7000000` 页启用 `MemoryAccessMonitor` | 启用成功，但 19 秒内**没有任何访问事件** |
| 早期在 `base+0x28B000` 页（t=2 s）启用 | 同样无事件 |

### 26.2 判断

- 映射创建极早（<0.6 s），解密很可能在随后 **几百毫秒内** 完成，t=2 s 再挂监控已经太晚。
- `base+0x7000000` 页也无事件，说明要么该页在监控启用前就被写完，要么壳自己的 `mprotect`/重映射把监控的页保护覆盖掉了。
- `MemoryAccessMonitor` 只给 `operation/address/size`，**不给 PC 和线程**；即使抓到，也要立刻对访问线程开 Stalker 才能定位写循环。

### 26.3 下一步

1. 在脚本加载时（t≈0）以 1 ms 轮询页内容 vs `classes.jar` 文件，测出每个页首次变明文的时刻，选一个「尚未解密」的页在解密前 1 ms 挂监控。
2. 或直接 Stalker 跟踪：`Stalker.follow` 主线程，在 `libDexHelper` 内的 store 指令上 callout，检查目的地址是否落在 `classes.jar` 映射页（需解析 `str/stp` 的基址+偏移）。
3. 抓到写循环 PC 后，回到静态反编译确认算法与密钥。

---

## 27. Store callout 抓写线程与解密时序（2026-11-11）

### 27.1 时序测量（1 ms 轮询页内容 vs 文件）

```
t=568 ms  检测到 classes.jar 映射（rw-, 0x7FD1000）
t=569 ms  偏移 +0x28BC0 处已是明文 'dex\n'
```

即：**映射创建与解密几乎同时完成**（≤1 ms 观测窗口）。这也解释了为什么：

- 在 t=2 s 挂 `MemoryAccessMonitor` → 太晚
- 在检测到映射后（t≈607 ms）再 `Stalker.follow` + store callout → 没有命中
- 之前所有「先等映射、再挂监控」的方案都抓不到写操作

### 27.2 Store callout 结果

- 只在 `libDexHelper` 范围对 `st*` 指令加 callout，检查 x0–x28 是否落在 jar 映射区间
- 从映射检测后开始 follow，运行 ~19 s：**0 命中**
- 原因判断：解密写入发生在这 10 ms 轮询间隙内；且写操作可能由 libc `memcpy/memset` 完成（不在 libDexHelper 内），而 `Interceptor` 挂 `memcpy/memset` 的脚本在当前 Frida 会话下报 `Failed to load script: operation was cancelled`，未能验证

### 27.3 结论

- 该壳的 classes.jar 解密是**启动极早期、毫秒级完成**的，Frida 侧「先观察后挂」的时序窗不够。
- 继续动态抓写的成本很高；更可行的是**静态**：在 `sub_3185C` 里 `0x364d4` 之前定位写 jar 映射的调用（大概率一次 `memcpy` 或自研循环），再配合已有 (ct, pt) 对做算法/密钥分析。

### 27.4 下一步

1. 静态审 `sub_3185C` 中 `0x33xxx–0x364d4` 段：找以 jar 映射基址/偏移为参数、长度为 0xBA3600 级别的调用。
2. 若确认是 `memcpy`/循环，回到密文/明文对判断是「XOR 流」还是「分组解密后拷贝」。
3. 用 Unicorn 重放该函数验证。

---

## 28. 静态审 sub_3185C：classes.jar 处理链（2026-11-11）

### 28.1 classes.jar 容器格式 **[观测]**

`classes.jar`（134,024,136 B）结构：

```
偏移 0x00        'dex\n038'      （普通 DEX 头，file_size 等字段有效）
偏移 0x20        LE32 file_size = 0x7FD0BC8 = 文件长度
file_size-8      LE32 section_off = 0x27BA8
file_size-4      'fdex'          （尾部标记）
section_off      LE32 count = 1
entry:
  +0x00  LE32 total_len = 0x7FA9014
  +0x04  LE32 name_len  = 8
  +0x08  'dexdata0'
  +0x10  LE32 data_len  = 0x7FA9000 (133,861,376)
  +0x14  data...
```

即 `dexdata0` 段几乎占满整个文件（0x27BC0 起，133.86 MB）。

### 28.2 解析/处理函数 **[观测]**

| 函数 | 作用 |
|---|---|
| `sub_58A08`（860 B） | classes.jar 主处理：拼路径（`.cache/classes.jar`）→ `access/mkdir` → 直接 `svc` `openat/read` → `crc32` → `sub_46188(...,"classes.dex",crc)` → `open` + `mmap(size, PROT_RW, MAP_PRIVATE)` → `sub_58D64` 校验 → 命中后返回 `dexdata0` 指针（并可走 `sub_58EFC` 解码路径）|
| `sub_58D64`（408 B） | 容器校验/定位：检查 `dex` 头、`file_size`、尾部 `fdex`、section 表，遍历条目找 `dexdata0`，输出 `(data_ptr, data_len)` |
| `sub_58EFC`（256 B） | 从 `dexdata0` 读 3 个 **大端** u32（0/4/8 偏移），`malloc(0x1008+n1+n2)`，`memcpy(+0xc, n1)`，再调 `sub_2D070` 解码 |
| `sub_2D070` → `0x7446C` | 分配 **0x176C8 字节**上下文并初始化，调用 `0x73E00` 做块解码；该尺寸与静态链接的 zstd DCtx 一致（库内存在 `g_ZSTD_threading_useless_symbol`） |

### 28.3 现状与矛盾点

- `dexdata0` 原始数据（`/tmp/dexdata0.bin`，133,861,376 B）中 **没有** zstd 魔数（`28 B5 2F FD`）、也 **没有** 第二个 `dex\n03`
- 以 3 个大端 u32 解析其头得到的是天文数字 → 说明当前构建走的是 `sub_58A08` 里 **flag!=0 的直通分支**（返回映射内指针，跳过 `sub_58EFC`），随后由 `sub_3185C` 后续代码对容器做就地变换（与动态观测到的「classes.jar 映射内出现明文 dex」一致）
- `sub_58A08` 在 `sub_3185C` 内的调用点：`0x333A0`、`0x34140`

### 28.4 下一步

1. 动态：对 `sub_58A08` 下 call probe，读**返回值**内容（`dex\n` 还是密文），确认走的是哪条分支
2. 静态：从 `0x333A0` 起到 `Load`（`0x364D4`）之间，找以容器指针/偏移为参数的 memcpy/循环，即就地解密/解压代码
3. 拿到后就可用已抓的 13 个明文 DEX 做算法验证

---

## 29. probe sub_58A08 返回值（2026-11-11）

### 29.1 返回值实测 **[观测]**

Stalker transform 在 `sub_58A08` 入口（`base+0x58A08`）与出口 `ret`（`base+0x58D5C`）下 callout：

```
ENTER 58A08  t=2746 ms  x0=0x7d33665630  x1=0x7fdfb62770
RET   58A08  t=3298 ms  x0=0x7c3ee7abc0  head=6f 70 18 47 90 bc b8 a9
```

- 函数内部耗时约 552 ms
- 返回值指向 `dexdata0` 数据（与文件偏移 0x27BC0 的内容一致），**返回时仍是密文**
- 说明当前构建走的是 `sub_58A08` 的直通分支（不调用 `sub_58EFC`）

### 29.2 明文出现时机 **[观测]**

在返回值 `buf` 上以 1 ms 轮询：

```
RET  t=3333 ms   buf+0x0000 head = 6f 70 18 47（密文）
     t=3343 ms   buf+0x1000 head = 64 65 78 0a（'dex\n'，明文）
```

**解密/解压发生在 RET 之后约 10 ms，写入目标是 `buf + 0x1000`**（与之前动态观测到的映射内偏移 0x28BC0 = 0x27BC0+0x1000 完全吻合）。

### 29.3 写操作抓取失败的原因

- 对 `buf+0x1000` 区间下 Stalker store callout（主线程；随后扩展到所有线程 + 线程观察者）：**0 命中**
- 关键限制：Stalker 的 transform 只在 **代码块首次翻译** 时决定是否插入 callout。解密代码在 `armed=true` 之前已被翻译过，后续再置位不会补插 callout，因此这个窗口抓不到
- 另一个可能是写入经 `mmap(MAP_FIXED)`/重映射或 `memcpy` 路径完成，而对应代码同样在置位前已被翻译

### 29.4 下一步

1. **预挂**：从 t=0 起对 `libDexHelper`（必要时加 `libdexjni`）范围内所有 `st*` 插入 callout，callout 内先判 `armed` 再判目的地址（代价可控，避免启动被拖慢）
2. 同时 hook `mmap/munmap/mremap/mprotect`（libc + 直接 svc 桩），确认 `buf+0x1000` 区间是否被重映射
3. 抓到写入 PC 后回静态确认算法（已有 13 组明文 DEX 可验证）

---

## 30. 预挂 store callout 与解码分支（2026-11-11）

### 30.1 预挂结果

- 从 t=0 起对 `sub_58A08` 出口下 arm callout，对 `libDexHelper`/`libdexjni` 范围内所有 `st*` 预挂 callout（callout 内先判 `armed` 再判目的地址）
- 本轮 `armed` 在 t≈10.5 s 生效（预挂拖慢了启动），但对 `buf+0x1000` 区间仍 **0 命中**
- 结合上一轮，可排除「`libDexHelper`/`libdexjni` 内的普通 `str/stp` 直接写入」；写入更可能来自 `memcpy/memset`（libc）、重映射、或别的模块

### 30.2 静态补充：解码路径受全局 flag 控制 **[观测]**

`sub_3185C` 内（`0x337A8` 起）：

```
ldrb w8, [global_0xed8 + 0xf]
cbnz w8, 0x34148          ; flag != 0 → 直接使用原始指针（不解码）
... 0x337B4: bl sub_58EFC ; flag == 0 → 走 dexdata0 头解析 + zstd 解码
```

`0x337CC` 分支同样：`mmap` 文件 → `buf = mmap + offset + 4` → `flag==0` 时 `sub_58EFC(buf)`，否则直达 `0x34148`。

本机实测 `sub_58A08` 返回密文、随后 10 ms 内在 `buf+0x1000` 出现明文，说明当前构建走的是 **flag != 0 的直通分支**，`sub_58EFC/zstd` 这条静态路径未被执行；容器由后续代码（或其它组件）处理。

### 30.3 下一步

1. 动态侧环境已不稳定（多次 `gum-js-loop` SIGSEGV addr 0x2、SIGTRAP），建议先重启 frida-server/设备再继续
2. 恢复后：hook `memcpy/memset`（本轮已能正常加载）+ 在 `0x34148` 之后对容器指针做写监测；或对 `0x34148` 起的代码做静态跟踪，找下一层解压/解密调用
3. 备选：直接对 `buf` 做逐页轮询，记录每页变明文的时刻，反推处理顺序与函数边界

---

## 31. 重启后动态环境状态（2026-11-11）

### 31.1 重启操作

- `adb reboot` → 开机完成
- `su -c 'cd /data/local/tmp && nohup ./frida-server-17.16.4 -l 127.0.0.1:49157'` 重新拉起（root，pid 正常）
- `adb forward tcp:49157`；`frida-ps` 正常
- spawn 恢复正常（先前 `setArgV0() slot` 错误消失）

### 31.2 基线

- `bypass_final + det_patch + msa_loop_off` 仅这三个脚本：进程存活 15 s+（pid 稳定）

### 31.3 加挂 hook 后的稳定性

| 组合 | 结果 |
|---|---|
| Stalker arm（58A08 ret）+ libc memcpy/memset/memmove Interceptor | Frida agent 自身 SIGTRAP（pc 在 `memfd:frida-agent-64.so`） |
| 仅 libc memcpy/memmove/memset Interceptor | 脚本加载正常，但 25 s 内未检测到 `classes.jar` 映射（本轮未见大 mmap） |
| 仅 libc mmap/mmap64 Interceptor | 无大 mmap 日志、20 s 定时器未执行；进程随后 SIGILL（addr 在 Frida agent 区） |

结论：**重启后该壳对额外 hook 的容忍度显著降低**，多加一个 Interceptor 就会触发自毁/SIGILL；baseline 三个 bypass 脚本不受影响。

### 31.4 下一步建议

1. 动态：改用「最小 hook + attach 模式」——先用 `am start` 启动，再 attach 只挂**单一**目标（如仅 `memcpy`），并去掉 `det_patch/msa_loop_off` 减少代码改动面
2. 或继续静态：审 `0x34148` 起的 flag!=0 分支，找容器指针的实际消费/解压代码
3. 已有 13 组明文 DEX 与 `classes.jar` 密文对，可在静态确认算法后直接验证

---

## 32. 静态审 0x34148 起的 flag!=0 分支（2026-11-11）

### 32.1 代码结构 **[观测]**

`0x34148` 起（`sub_3185C`）：

1. 保存容器指针到 `[sp+0x18]`，从全局 `[0xED8]` 取计数/标志，`malloc` 两组数组（`count*8`、`count*4`）
2. `0x341E0`：`ldrb w12,[global+1]`，非零则跳 `0x3483C`（另一分支）
3. `0x34210`–`0x3424C`：从 `0xC713A` 处按字节复制 **0x1000 字节** 到栈上（`sp+0x300`），循环上限 `1<<12`
4. `0x34250`–`0x34570`：大量 `umov/fmov/ushll/shl/orr` 向量操作，从全局上下文（`x26`）取 64 字节，构造 4 个 16 字节块，写入 `sp+0x100`，然后调用 `sub_457A4`
5. `0x34588`–`0x34610`：`malloc(0x50)` 并从 `0xC28E0` 复制 80 字节（**斐波那契数列**：0,1,1,2,3,5,8,13,21,34,…）；再 `malloc(0x40)` 复制 64 字节；`malloc(0x10)`
6. `0x34610` 起：用 64 字节缓冲里的 16 位值做**表索引**（`ldpsw`），从 `0xC714A` 查表后与 `sp+0x100` 的字节 `eor` —— 表驱动替换 + 异或的轮函数

### 32.2 判断

- 这不是标准 AES：文件里没有 AES S-box；`0xC713A` 区域在静态镜像里是 0，说明 **4 KB 表在运行时生成**（与之前动态观察到的高熵密钥流、无短周期一致）
- 80 字节斐波那契表被当作密钥/参数表使用，配合向量化的 key schedule，指向**自研分组/流密码**
- 静态镜像中 `0xC713A` 为空，因此无法直接从文件里取表；需要运行时内存或 Unicorn 模拟该段代码

### 32.3 下一步

1. 用 Unicorn 模拟 `sub_3185C` 的相关片段（`0x34148`–`0x34700`），以捕获的容器指针为输入，观察表构造与轮函数输出
2. 或动态读取 `0xC713A` 处的运行时表（进程内存），再离线复现解密
3. 已有 13 组 (ct, pt) 可与模拟结果直接比对

---

## 33. 无 hook 读运行时表（2026-11-11）

### 33.1 执行结果

在 `bypass_final + det_patch + msa_loop_off` 基线下，仅在 t=3000/3500/4000/5000 ms 做**纯内存读取**并落盘（不挂任何 Interceptor/Stalker）：

```
base 0x75e1972000
table_*  4096 B  head = 00 00 00 00 00 00 00 00   （全 0）
fib_*      80 B  head = 00 00 00 00 01 00 00 00   （斐波那契表，静态一致）
win_*    8192 B  head = 00 75 00 78 00 6a 00 66   （UTF-16 数据，非代码）
```

- 进程全程稳定（≥6 s），说明**纯读取不触发自毁**
- `0xC713A` 在 3–5 s 内一直是全 0 → 它并不是运行时的 4 KB 密码表

### 33.2 重新解释

`0x34210` 的 0x1000 字节循环只是把 `sp+0x300` 的工作缓冲区按源页初始化（源页为 0），**真正的表/密钥扩展在后面的调用里**：

| 调用点 | 函数 | 大小 | 推断 |
|---|---|---|---|
| `0x34570` | `sub_457A4` | 2532 B | 密钥扩展：`(result, a2)`，输入 `sp+0x38`/`sp+0x100` |
| `0x34598` | `sub_45374` | 1072 B | 轮函数/加解密：`(sp+0x100, sp+0x300, ...)` |
| `0x345FC` 后 | 表驱动替换 | — | 用 64 字节种子+`0xC714A` 查表 eor |

表/轮密钥应在**栈或堆**，不在模块镜像里，所以静态读取模块地址拿不到。

### 33.3 下一步

1. **静态**：读 `sub_457A4` 与 `sub_45374` 的伪代码，确定 key schedule 与轮函数（Fibonacci 表 + 64 字节种子）
2. **无 hook 差分扫描**：在 t=3.0 s 与 t=4.0 s 各快照一次堆/匿名 rw 区间，对 4 KB 块做哈希差分，找出新生成的高熵表（无 hook，安全）
3. 拿到表后离线复现解密，与 13 组 (ct, pt) 验证

---

## 34. sub_457A4 / sub_45374 静态结论（2026-11-11）

### 34.1 `sub_45374`：Merkle–Damgård 哈希的 update/final **[观测]**

- 上下文 `a2` 布局：`a2[0..1]` 位长度（64 位），`a2+2..+5` 为 256 位状态，`a2+6..` 为 64 字节块缓冲，`+24` 起为填充区
- 典型 SHA-256 式填充：`(bits>>3)&0x3F >= 0x38 ? 120 : 56`，补位后写 64 位长度
- 每满 64 字节调用 `sub_457A4(a2+2, block)` 做压缩；结束时把状态拷到 `a1`
- 与 SHA-256/SM3 的区别：**库内不存在** SHA-256 IV、SM3 IV、SM3 常量（`7380166F…`、`79CC4519`、`7A879D8A` 全部未命中）

### 34.2 `sub_457A4`：自定义 256 位压缩函数 **[观测]**

- 2532 B、约 150 个局部变量，纯整数/向量运算，无系统调用、无外部依赖
- 输入 `(state, block)`，输出写回 state；无标准哈希常量 → **自研压缩函数**（可能做了 S 盒置换/消息扩展改造）
- 调用点：`0x34570`（4×16 字节块）、`0x45374` 内部（每块）、`0x345FC` 后续的表驱动轮函数

### 34.3 对目标的意义

- `0x34148` 分支实际在做 **哈希式密钥派生 + 表驱动变换**，而不是 AES/常规分组密码
- 由于 `sub_457A4`/`sub_45374` 是**纯函数**，Unicorn（已在本项目可用）足以直接模拟，无需 unidbg
- 目前缺的是：初始 state/密钥从哪里来（全局上下文 `x26`、斐波那契表、`classes.dve` 24 B），以及每块数据如何与之异或

### 34.4 下一步

1. 用 Unicorn 单独模拟 `sub_457A4` 与 `sub_45374`，用构造输入确认其输出（验证是否 256 位哈希）
2. 无 hook 差分扫描堆内存，定位运行时生成的 64 字节种子 / 4 KB 表
3. 组合出完整 keystream 生成器，用 13 组 (ct, pt) 验证

---

## 35. Unicorn 模拟 sub_457A4 / sub_45374（2026-11-11）

### 35.1 工具

`analysis/tools/unicorn_hash.py`：映射 `libDexHelper.dec.so` 三个 LOAD，设置栈/TLS/哨兵，直接调用两个函数。

### 35.2 结果 **[观测]**

```
457A4(state=0,  block=0)    → 971ccdf7813648a532d8682b39a60cf9   (写回 16 字节)
457A4(state=0..31, block=0..63) → 6d2211bd885c03495239d2ebd07dbc23

45374(ctx: MD5 IV @+8, empty msg) → ee129d4461935005b3494d60cbd96fa9
45374(ctx: 全 0, empty msg)       → 91312912a3e3cef000e8052a155c74c5
```

- `sub_457A4` 的输入/输出状态是 **128 位（16 字节）**，块长 64 字节 → **MD5 结构**
- `sub_45374` 的输出 16 字节，且把结果同时写回 ctx（`ctx+0x58` 处可见）
- 二进制中存在 **MD5 IV**（`0x67452301…` 小端，位于 `0x796832`）
- 但以 MD5 IV + 空消息模拟得到的摘要 **不是标准 MD5**（标准应为 `d41d8cd98f00b204e9800998ecf8427e`）

### 35.3 结论

- 这是一个 **改造版 MD5**（128 位、64 字节块、MD5 IV 保留，T 表/消息扩展可能被替换或运行时生成）
- 与前面的斐波那契表、表驱动轮函数一致：壳用 **自研哈希派生密钥流**
- 由于两函数是纯函数，Unicorn 可直接用于后续逐块复现；不需要 unidbg

### 35.4 下一步

1. 对比标准 MD5 压缩与 `sub_457A4` 在单个已知 64 字节块上的中间轮，定位被修改的常量/步骤
2. 检查 T 表是否运行时由斐波那契表/全局状态生成（无 hook 差分扫描堆）
3. 复现完整哈希后，验证它与 13 组 (ct, pt) 的 keystream 关系

---

## 36. 与标准 MD5 对比：`sub_457A4` 就是标准 MD5 压缩（2026-11-11）

### 36.1 常量与轮函数 **[观测]**

- `sub_457A4` 内联常量提取（`mov/movk` 组合）得到 63/64 个值，前 8 个与 MD5 K 表完全一致：
  `d76aa478, e8c7b756, 242070db, c1bdceee, f57c0faf, 4787c62a, a8304613, fd469501`
  （差值仅是解析漏掉 1 个常量导致的下标错位，不是常量不同）
- 64 条 `ror` 立即数：
  - R1 `25,20,15,10` = 32 − (7,12,17,22) → MD5 第 1 轮
  - R2 `27,23,18,12` = 32 − (5,9,14,18→20) → MD5 第 2 轮
  - R3 `28,21,16,9` = 32 − (4,11,16,23) → MD5 第 3 轮
  - R4 `26,22,17,11` = 32 − (6,10,15,21) → MD5 第 4 轮
- 操作码分布：`add 260 / mov 64 / ror 64 / movk 63 / eor 47 / and 32 / bic 32 / orr 32 / orn 16` —— 与 MD5 的 F/G/H/I 实现一致

### 36.2 Unicorn 验证 **[观测]**

```
sub_457A4(标准 MD5 IV, 空消息填充块 0x80||0…0) → d41d8cd98f00b204e9800998ecf8427e
标准 MD5("")                                    → d41d8cd98f00b204e9800998ecf8427e
```

**结论：`sub_457A4` 就是标准 MD5 压缩函数，`sub_45374` 是标准 MD5 的 update/final。**

### 36.3 修正

- 之前「自研压缩函数/改造版 MD5」的判断**不成立**
- 之前的 `45374(ctx: MD5 IV @+8, 空消息)` 得到非标准摘要，是因为**上下文布局/初始状态位置假设错误**，不是压缩被改
- 真正的定制点在**初始状态（自定义 IV / keyed MD5）**，它由 `0x34148` 分支用全局上下文 + 斐波那契表构造

### 36.4 下一步

1. 精确定位 `sub_45374` 的上下文布局（state/缓冲/长度字段偏移），用 Unicorn 复现标准 MD5 流式摘要
2. 从 `0x34148` 分支静态还原自定义 IV（或动态读取压缩入口的 16 字节 state）
3. 用 keyed-MD5 复现 keystream，与 13 组 (ct, pt) 验证

---

## 37. 自定义 IV 还原结果（2026-11-11）

### 37.1 结论：IV 就是标准 MD5 IV **[观测]**

在 `sub_457A4` 入口下 callout（Stalker），读取 `x0`（state）与 `x1`（64 字节 block）：

```
#1 state=0123456789abcdeffedcba9876543210   block=000129e966b250b8…1abf 00…00
#2 state=575ef4619fcdf510c684b1e7bff1ba91   block=80 00…00 | len=0x200 (512 bit)
#3 state=0123456789abcdeffedcba9876543210   block=全 0
#4 state=ac1d1f03d08ea56eb767ab1f91773174   block=全 0
#5 state=145b0dcd845d010449402e3132296610   block=全 0
#6 state=027a8400d09a96101d9ca1763dedbe29   block=全 0
```

- 初始 state **就是标准 MD5 IV**，不存在自定义 IV
- 之前把 `+8` 位置的状态读错，才误以为 IV 被改

### 37.2 定制的真正来源：模块内静态种子块 **[观测]**

- `#1` 的 64 字节 block（`blk_1`，22 字节数据 + 42 个 0）在 `libDexHelper.dec.so` 中命中：
  - 文件偏移 `0xE9C90` 附近（LOAD#2 数据段，vaddr ≈ `0xEAC90`）
  - 附近还有 `dex\n035` 等数据 → 是一段内嵌的密钥/数据块
- **`MD5(blk_1) = eaead842e35e752b5903287ea6ad3ddd`**
- 这与磁盘上 `classes.dve` 的前 16 字节**完全一致**：

```
classes.dve = ea ea d8 42 e3 5e 75 2b 59 03 28 7e a6 ad 3d dd | 8c c3 e2 6a | 00 00 00 00
              └──────────── MD5(seed) 16B ────────────┘        4B 校验/版本   4B 保留
```

即：`classes.dve` 是壳用内置种子算出的 MD5 摘要（+ 8 字节附加字段），用于校验/派生。

### 37.3 已验证的复现

- Unicorn 调用 `sub_457A4(标准 IV, blk_1)` → `575ef4619fcdf510c684b1e7bff1ba91`（与运行时 `#2` 状态一致）
- 再用 `blk_2`（0x80 填充 + 长度 512）压缩 → 摘要 `eaead842…`（与 `classes.dve` 一致）
- `hashlib.md5(blk_1)` 同样得到 `eaead842…`，说明就是标准 MD5

### 37.4 下一步

1. 确认 `classes.dve` 后 8 字节（`8cc3e26a 00000000`）的含义与校验流程
2. 从 `#3–#6` 的全零块链推断 keystream 生成方式（候选：MD5(seed‖counter) / MD5 链）
3. 用 `pt XOR ct` 的 keystream（首 16 字节 `0ecdac1a…`）比对候选，确定最终密钥流布局

---

## 38. keystream 比对结果与模型修正（2026-11-11）

### 38.1 MD5 零块链已验证 **[观测]**

运行时捕获的状态序列与离线计算完全一致：

```
s0 = 标准 MD5 IV
s1 = compress(s0, 0^64) = ac1d1f03d08ea56eb767ab1f91773174
s2 = compress(s1, 0^64) = 145b0dcd845d010449402e3132296610
s3 = compress(s2, 0^64) = 027a8400d09a96101d9ca1763dedbe29
```

即壳运行了一条 **MD5 零块 PRNG/KDF 链**（每步对全零 64 字节块做压缩）。

### 38.2 `pt XOR ct` 不是密钥流 **[观测]**

对 `classes.jar[0x28BC0:]` 与内存明文 DEX 逐字节 XOR 得 `ks`，分析：

| 检查 | 结果 |
|---|---|
| `ct → pt` 是否为函数（同一 ct 字节是否总映射同一 pt 字节） | **否**（256/256 个 ct 值都有多值） |
| 小滞后重复率（16/32/64/256/1024/4096/8192） | 0.20–0.32（远高于随机 0.0039） |
| 滞后 4097 | 0.044（骤降） |

- 存在局部相关性，但**位置映射不是一一对应** → `pt` 不是 `ct` 的逐位置变换
- 结合「明文出现在 `buf+0x1000`」这一事实，最合理解释：**解压输出被写回映射内固定偏移**，`pt` 与 `ct` 不对齐，因此 `pt XOR ct` 不是密钥流

### 38.3 模型修正

- 之前的「流密码/CTR」推断**不成立**
- 真实流程更可能是：`dexdata0`（压缩/编码容器）→ **自定义解压器**在映射内就地解压到 `buf+0x1000`，MD5 零块链作为解压器的 PRNG/参数
- 用项目的 LZSS 解码器（`sub_108914` 格式）直接解 `dexdata0`/`0x28BC0` 均失败 → 不是该格式

### 38.4 下一步

1. 静态：在 `0x34148` 之后的循环（`0x34610` 起，表驱动 + XOR）中找解压主循环，确认输入/输出指针与窗口
2. 动态：捕获解压器入口参数（dst=`buf+0x1000`、src=`dexdata0`、len）与 MD5 链的使用方式
3. 复现解压器后用 13 组 DEX 校验

---

## 39. 0x34610 主循环还原：标准 SM4-ECB + 静态派生密钥，**不是白盒**（2026-11-11）

### 39.1 结论先行

- `0x34610` 起的不是自定义解压器，而是 **DEX 条目的 SM4 解密路径**；§38.3 的「自定义解压器」推断作废。
- 算法是 **标准 SM4（GB/T 32907-2016）ECB**，代码里没有自研密码。
- **不是「密钥白盒化保护」**：4 张 T 表与公开标准常量逐字节一致，密钥扩展用公开 FK/CK 常量，16 字节密钥由「静态常量 ⊕ 包名」直接算出。
- 端到端复现成功：解出的 **14/14 个 DEX 与动态捕获明文 MD5 完全一致**，DEX adler32 校验全部通过。

### 39.2 条目解密循环（0x34898 起）**[静态]**

```
0x34898  malloc(0x30)                     ; 条目描述结构
0x348b8  记录 = table + i*16               ; {u32be offset, u32be size, 8B 0}
0x348e0  src  = dexdata0 + 0x1000 + offset
0x3490c  key  = *(0xf2c10)                 ; 16 字节全局密钥指针
0x34918  size = min(size, 0x20000)         ; 单个条目每次最多解 0x20000 字节
0x34928  malloc(0x80)  -> ctx              ; 32 个轮密钥 = 0x80 字节
0x3493c  sub_37B78(key, ctx)               ; SM4 密钥扩展
0x34944  malloc(size)  -> buf
0x34970  sub_37CC4(src+i, buf+i, ctx)      ; 每 16 字节一个分组，ECB
0x3498c  memcpy(src, buf, size & ~0xf)     ; 就地写回
0x34990  free(ctx); free(buf)
```

### 39.3 `sub_37B78` = 标准 SM4 密钥扩展 **[静态 + 验证]**

- 从 `x0` 读 16 字节密钥，`rev` 成 4 个大端字；
- 异或 SM4 公开 FK：`0xA3B1BAC6 / 0x56AA3350 / 0x677D9197 / 0xB27022DC`（0x37b8c–0x37bd8）；
- CK 常量表在 `0xc5b60`（`adrp 0xc5000 + 0xb60`），S-box 在 `0xc5be0`；
- 轮函数 `L' = x ^ rotl13 ^ rotl23`（`extr ...,#0x13` / `#9`）；
- 循环 `cmp x9,#0x20`，32 个轮密钥**明文**写到 `x1`（ctx），每个 4 字节。

### 39.4 `sub_37CC4` = 32 轮 T 表 SM4 解密 **[静态 + 验证]**

- 4 个表基址：`T0 = 0xc5ce0`（静态），`TBOX0/1/2` 经 GOT 槽
  `0xe9c20/0xe9c30/0xe9f78`（`R_AARCH64_GLOB_DAT`）解析到
  `0xEA000/0xEA400/0xEA800`（ph1，加载时解密）。
- 轮结构：`Y = X1^X2^X3^rk`，`X4 = X0 ^ T0[Y>>24] ^ T1[(Y>>16)&255] ^ T2[(Y>>8)&255] ^ T3[Y&255]`，
  共 32 轮，轮密钥从 `ctx[0x00..0x7C]` 依次读取（解密方向）。
- 与公开标准 T 表逐项比对：

| 表 | 地址 | 与标准表不一致项 |
|---|---|---|
| T0 | 0xc5ce0 | 0 / 256 |
| T1 | 0xEA000 (TBOX0) | 0 / 256 |
| T2 | 0xEA400 (TBOX1) | 0 / 256 |
| T3 | 0xEA800 (TBOX2) | 0 / 256 |

  标准 S-box 也在 `0xc5be0`，与 GB/T 常量一致。

### 39.5 密钥派生（0x34600–0x34834）**[静态 + 验证]**

- `0x34600–0x34744`：用 4KB 工作表（常量表 `0xc713a` 生成）+ `sub_45374`（MD5）
  与 0x40 字节 LUT（`0xc714a`）异或，得到一组候选 16 字节；
- `0x34748–0x3481c`：把 16 字节常量 `0xc2a50` 与 `*(0xf13f8)+0x88` 处字符串
  逐字节异或（`key[0] = str[0] ^ 0x66`，常量首字节正是 `0x66`）；
- `0x3482c`：`*(0xf2c10) = x20`，`0x34834`：`*x20 = key16`；
- 生命周期：每个条目都重新 `sub_37B78(同一 key)`，密钥在整个进程内固定。

实测：

```
KDF_CONST16 = libDexHelper.dec.so @0xc2a50 = 66 97 6c e8 6d 46 38 b0 09 5a a5 d7 0f cb 9a a0
key16       = KDF_CONST16 XOR "com.example.reference"[:16]
            = <redacted-derived-key>
```

即密钥只与 **so 内静态常量 + 包名** 有关，与设备、账号、安装路径无关。

### 39.6 容器布局与「只加密前 128KB」**[静态 + 验证]**

```
classes.jar
  0x00000   伪 DEX 头（dex\n038）+ 伪结构
  0x27ba0   fdex section 描述 + "dexdata0" 名（0x27bb4）
  0x27bc0   dexdata0 起点
    +0x0000 .. +0x0FFF   段头（含条目表）
    +0x0F20 .. +0x0FFF   14 条记录：{u32be offset, u32be size, 8B 0}
    +0x1000 + offset_i   第 i 个 DEX：
                          前 0x20000 字节 = SM4-ECB 密文
                          其余              = **明文**
```

14 条记录（offset 相对 dexdata0+0x1000）：

| # | offset | size |
|---|---|---|
| 0 | 0x0 | 16167180 |
| 1 | 0xF6C000 | 12203520 |
| 2 | 0x1B10000 | 12111240 |
| 3 | 0x269D000 | 10061776 |
| 4 | 0x3036000 | 12858436 |
| 5 | 0x3C7A000 | 12063284 |
| 6 | 0x47FC000 | 10793400 |
| 7 | 0x5248000 | 5804368 |
| 8 | 0x57D2000 | 4314184 |
| 9 | 0x5BF0000 | 8803412 |
| 10 | 0x6456000 | 8615800 |
| 11 | 0x6C8E000 | 15069456 |
| 12 | 0x7AEE000 | 1941504 |
| 13 | 0x7CC8000 | 3013160 |

这与代码里 `size = min(size, 0x20000)` 的截断完全吻合：**每个 DEX 只加密头部 128KB，之后是明文**。

### 39.7 复现与验证 **[验证]**

- `analysis/tools/sm4.py`：纯标准 SM4，国标测试向量
  `0123456789ABCDEFFEDCBA9876543210` → `681EDF34D206965E86B3E94F536E4246` 通过；
- `analysis/tools/fdex_unpack.py`：按 §39.5/39.6 直接解容器：

```
python3 -I analysis/tools/fdex_unpack.py \
  classes.jar libDexHelper.dec.so com.example.reference outdir
key=<redacted-derived-key>  dexdata0=0x27bc0  table=0x28ae0  entries=14
wrote 14 files
```

- 输出与 `analysis/dexcap_dynamic/` 的动态捕获逐项比对：
  **14/14 MD5 一致**，且每个 DEX 的 `adler32(header[12:])` 校验通过。
- 交叉验证：对已知明文块 SM4 加密后在容器内定位，偏移差 delta=0；
  0x20000 之后的「密文」实为明文（直接可读）。

### 39.8 回答：这部分是不是梆梆宣传的「密钥白盒化保护」？

**不是。** 白盒密码学的定义是：密钥被融进查找表/编码，攻击者拿到完整实现也无法提取密钥。
本节证据逐条否定：

1. 4 张 T 表与 GB/T 公开常量逐字节相同（0/256 差异）——没有密钥化编码；
2. 密钥扩展 `sub_37B78` 就是公开 SM4 密钥扩展，32 个轮密钥**明文**常驻内存；
3. 16 字节密钥 = so 内静态常量 ⊕ 包名，两项都静态可得，甚至不需要运行 App；
4. 攻击面还有：只加密前 128KB、其余明文；密钥对设备/安装无绑定。

因此它属于 **「自解密壳 + 反调试 + 密钥拼装 + 部分加密」的隐藏式保护**，而不是白盒密码。
「白盒」在宣传口径上可能泛指「密钥不裸奔」，但从密码工程角度不成立。

### 39.9 待办

1. 其它版本的 `classes.jar` 是否也只加密前 0x20000（若全量加密，算法仍同）；
2. `classes.dve`（`eaead842…3ddd | 8cc3e26a | 0`）未参与本条链路，需单独定位其用途；
3. `sub_2CB30`/`sub_2D070`/`sub_58EFC` 等第二层处理（flag==0 分支）仍未动态验证。

---

## 40. `classes.dve` 的用途（2026-11-11）

### 40.1 结论

`classes.dve` 是壳维护的 **24 字节「构建/缓存版本戳」**（对应符号 `vtag`），不是密钥、不参与
`classes.jar` 解密（§39 已证明密钥 = `0xc2a50` 常量 ⊕ 包名，14/14 复现）。

用途：让壳在每次启动时判断「这次运行的环境（壳版本 / oat 缓存）是否与上次一致」，
把结果（0/1/2）交给 DEX 加载驱动 `sub_41F80`，决定复用上次内部状态还是重建，
并在重建时把加密策略标记 `.edata` 落盘。

### 40.2 文件内容 **[观测 + 静态]**

设备 `/data/data/com.example.reference/.cache/classes.dve`（24 B）：

```
eaead842 e35e752b 5903287e a6ad3ddd | 8cc3e26a 00000000
└────────── 16 B ──────────┘   └──── 8 B ────┘
```

| 字段 | 含义 | 证据 |
|---|---|---|
| `[0:16]` | `MD5(vtag[0:64])`，`vtag` = so 内 `0xEAC90` 处 64 字节固定种子块（文件 `0xe9c90`） | 运行时捕获的 blk_1 与该常量逐字节相同，且 `MD5(blk_1)=eaead842…` |
| `[16:24]` | 上次写入时 `fstat(<oat/dex 缓存>).st_ctim.tv_sec`（Linux arm64 `struct stat+0x68`） | 0x31b48–0x31b60：`fstat(fd, sp+0x300)`；`ldr x8,[sp,#0x368]`；`str x8,[vtag+0x10]` |

`vtag` 不是只读常量：符号 `vtag` 位于可写数据段，`sub_45374`（MD5 final）直接把摘要写进
`vtag[0:16]`，再写 `vtag[16:24]`，最后整体 `fwrite(&vtag, 1, 0x18, fp)` 到 classes.dve。

### 40.3 写入 / 比对逻辑（sub_3185C，0x31b28–0x32110）**[静态]**

1. 构造路径 `<dataDir>/.cache/classes.dve`（`snprintf("%s%s/%s", …, "classes.dve")`）；
2. 计算 `MD5(vtag)` → 写入 `vtag[0:16]`；`vtag[16:24] = fstat(oat).st_ctim`；
3. `access(path, F_OK)`：
   - **不存在** → `fopen(path,"w")` + `fwrite(vtag,1,24)` → 状态 **2**
   - **存在** → `fread` 24 B 到栈；`memcmp(file[0:16], vtag[0:16], 16)`：
     - 一致 → 状态 **0**；若 `file[16:24] != vtag[16:24]` 仅静默重写（状态不变）
     - 不一致 → 重写 → 状态 **1**
4. `sub_41F80(info+136, info+608, 状态, 0, …)`。

被 `fstat` 的路径（SDK ≥ 28 分支，0x319b8–0x31a34）：取 `info+0x260` 的最后一级目录，
拼成 `…/<str@0xc3fa4>/<info+0x30>/<basename>`，再把末尾 3 字符替换为 `odex`
→ **`…/oat/<arch>/<name>.odex`**（壳自己的 oat 缓存）。

### 40.4 状态值在 `sub_41F80` 中的作用 **[静态]**

- `a3 == 0`（版本戳有效）：调用 `sub_462C8(&xmmword_F1940, …)` 复用已有内部状态/策略；
- `a3 == 1/2`（版本变化 / 首次运行）：走重建分支；函数末尾（`if (a3)`）
  写出 `.edata`：先 `enc_type/<dword_F1630>`，再逐条追加策略（如
  `shared_prefs/*.xml`、`!databases/nebula_app.db`）。

设备上 `.edata` = 55 B：

```
enc_type/0
shared_prefs/*.xml
!databases/nebula_app.db
```

时间线与状态机吻合：`.edata` mtime = 安装日 10-27（首次运行，状态 2）；
11-05 payload 更新后壳版本未变（状态 0），故 `.edata` 未重写，但 `classes.dve`
因时间戳字段变化被刷新。

### 40.5 与 RNA/密钥链路的关系

- 与 `classes.jar` 解密**无关**：删除 classes.dve 后壳只会重建它；解密仍成立（§39）。
- `.edata` 只在壳内写入；在 libDexHelper 中未发现读取点，14 个业务 DEX（Java 层）
  也不含 `enc_type`/`.edata`/`classes.dve` 字符串 → 属壳内部状态，或供壳生态其它组件/云端使用。
- 观测注意：设备上存的时间戳（`0x6ae2c38c` = 2026-10-15）与当前 `base.odex/vdex/art`
  的 ctime（2026-10-29）不一致，且全盘无该 ctime 的文件 → 说明它是**历史快照**
  （目标 oat 文件已被清理，或写入时设备时钟不同），不代表当前环境。

### 40.6 一句话

`classes.dve` = “壳版本 + oat 缓存状态”的本地失效标记；`.edata` = 状态失效时导出的
加密策略标记。二者都是壳的**缓存/诊断状态**，不是 DEX 解密密钥材料。

---

## 41. `info.y` 的用途：反注入 / 反脱壳检测规则库（2026-11-11）

### 41.1 结论

`info.y` **不是**加密数据、也不是 DEX 容器元数据，而是壳的
**检测规则/保护策略程序**（server 可随 APK 更新）：里面是 Frida / Xposed / EdXposed /
TaiChi / Youpk / FUPK3 / FART / YARFA hook / RootHide 等框架的特征串、ART 内部符号、
系统属性参数，以及一组占位符变量。壳在运行时从 APK 资源 `assets/info.y` 释放到
`<dataDir>/.cache/info.y`，并做 MD5 完整性校验。

### 41.2 文件来源与落盘 **[静态 + 观测]**

- 字符串 `"assets/info.y"`、`".cache/info.y"` 位于 `libDexHelper.dec.so`
  `0xC3EE6` / `0xC3EED` 附近；
- 引用函数 `sub_4B4F0`（JNI 入口，`a1=JNIEnv*`）：
  - `sub_46188(apkPath, &buf, "assets/info.y", 0)` 从 APK 取资源；
  - `snprintf("%s%s", dir, ".cache/info.y")` → `open/write/close` 落盘；
  - 上层还有一个「文件守护」循环，反复检查/补回该文件；
- 设备观测：`/data/data/com.example.reference/.cache/info.y`，9586 B，
  mtime 与 classes.jar 同批（2026-11-05 14:59），说明随 payload 一起更新。

### 41.3 文件格式 **[静态 + 验证]**

```
+0x00  "INFO-"                     5 B  magic
+0x05  16 B                         MD5(body)  —— 实测 md5(d[0x16:]) 与这 16 字节完全相等
+0x15  0x0C                        1 B  记录数（12，≤16）
+0x16  12 × {u32 offset, u32 flags, u32 size}   各 arena section 的记录
        sections 按 offset 连续排列（0xA6 → 0x1EC2）
+0x1EC2 214 × {u32 section, u32 offset}          yr_arena_ref_to_ptr 重定位表
        0x746 起在 section 5 中              字符串池（NUL 分隔）
```

> 详细结构见 §51；早期把 `0xA6` 读成“166 条目”的表述已作废（§45.6 第 5 条）。

- 完整性：`md5(info.y[0x16:]) == info.y[5:21]`（已逐字节验证），篡改会被壳拒绝；
- 字符串池（0x746–0x9B5）内容（节选）：

| 类别 | 字符串 |
|---|---|
| 框架名 | `default`、`roothide`、`edxposed`、`xposed`、`taichi`、`fupk3`、`youpk`、`fart`、`yarfahook` |
| 特征串 | `Start to dump all dex files`、`Unable to found fupk interface`、`shouldUnpack`、`Unpacker`、`dumpArtMethod`、`dumpdexfilebyArtMethod`、`myfartInvoke` |
| ART 内部 | `art::JavaVMExt::AddGlobalRef`、`art::ClassLinker::VisitClassLoaders`、`addJarToClasspath` |
| 系统属性 | `pm.dexopt.bg-dexopt`、`inline-max-code-units=0`（壳会设置/检查，抑制 ART 优化与 dump） |
| 占位符 | `$hidestring`、`$word0000_text_string`、`$string1`、`$feature1..3`、`$symbol32_1/2`、`$symbol64_1/2` |
| 其它 | `_Z12hide_unmountv`、`./lib/android`、`ljagD`/`GedlflY`（隐藏路径/名称） |

`166` 之后的二进制区是规则程序/表（出现 `03/06/0A/0D/16/1C/1D` 等小整数操作码样式 +
`0xFFFFFFFF` 哨兵），与字符串池配合构成一套可解释的检测规则。

### 41.4 消费端证据 **[静态]**

- `libDexHelper` 内置同一套检测词表：`frida_agent_main`、`DexposedBridge`、
  `dexposedIsHooked`、`dexposedCallHandler`、`adbi_hook`、`hook_precall`、`hook_postcall`、
  `dalvik_java_method_hook`、`art_java_method_hook`、`MSFindSymbol`、`ALLINONEs_arthook`、
  `ddi_hook`、`dexstuff_*` 等（`sub_530B0` 按 15 类签名逐一比对）；
- `sub_4E9F0` 直接 `openat("/proc/self/maps")`（`0xC312C`），对映射做扫描；
- 因此 info.y 是给这套 **反注入 / 反脱壳 / 反 dump 引擎** 的**可更新规则源**：
  框架升级（如新版 Frida/Xposed）后无需重发 .so，只更新 APK 里的 info.y 即可。

### 41.5 与 DEX 解密链路的关系

- **无关**：`classes.jar` 解密只用 `0xC2A50` 常量 ⊕ 包名（§39），14/14 DEX 复现已验证；
- 删除/替换 `.cache/info.y` 只会触发壳的重新释放与完整性校验失败，不影响 DEX 解密本身；
- 它属于壳的**运行时对抗配置**，与 `classes.dve`（缓存失效戳，§40）同属壳自身的状态文件。

### 41.6 一句话

`info.y` = 壳的「反调试/反注入/反脱壳规则包」（含框架特征、ART 符号、系统属性与占位符，
`INFO-` 头 + MD5 完整性校验），运行时从 `assets/info.y` 释放到 `.cache/info.y`，
供壳内检测引擎消费；不是加密材料。

---

## 42. `.edata` 的用途：透明文件加密策略状态（DVE）（2026-11-11）

### 42.1 结论

`.edata`（`<dataDir>/.edata`，隐藏文件）是壳的 **透明文件加密（DVE）策略状态文件**：

- 第 1 行 `enc_type/<N>` 选择文件内容加密算法（本机 `N=0` → **RC4**）；
- 其余行是 **路径规则**：需要加密的路径模式 + `!` 前缀的排除项；
- 壳启动时读取它恢复策略，在「首次运行 / 壳版本变化」时重写；
- 与 DEX 解密链路无关（§39）。

设备实测 55 B：

```
enc_type/0
shared_prefs/*.xml
!databases/nebula_app.db
```

### 42.2 读写位置 **[静态 + 观测]**

全部集中在 `sub_41F80`（JNI 保护引擎初始化，0x41F80–0x4528C）：

| 动作 | 地址 | 说明 |
|---|---|---|
| 拼路径 | 0x41FBC–0x41FE0 | `snprintf("%s%s", dir, ".edata")` |
| 存在性 | 0x41FE8 | `access(path, F_OK)` |
| **读/解析** | 0x42644–0x42860 | `fopen(path,"r")` + `fgets` 逐行；`"enc_type/"` 前缀行用 `strrchr('/')+atoi` 解析到 `[0xF1B80]`；其余行 `malloc+memcpy` 加入规则数组 `[0xF1940]`（最多 0x200 项） |
| 规则归一化 | `sub_462C8` | 对规则按固定模式补 `!` 排除位（`entry[4]/entry[8]='!'`） |
| **写** | 0x43D64–0x43EC0 | `fopen(path,"w")`；先写 `enc_type/%d`（取 `[0xF1630]`），再逐条写规则（`strncmp` 补 `/`），每项一行 |

写入受 `classes.dve` 状态（`a3`）控制：`a3 != 0`（首次/壳版本变化）才重写（§40.4）。

### 42.3 行格式与语义

- `enc_type/<N>`：算法/模式编号。`N=0` 时进入 **RC4 风格流加密**分支：
  - 0x47100 从 `0xC60EC` 拷入 256 字节 **身份 S 盒**（实测 `00 01 02 … FF`）；
  - KSA/PRGA 使用 `[0xF1EF0]` 处的 **16 字节密钥**（密钥下标按 mod 16 循环）；
  - 该密钥 = `so@0xEADF8` 的 16 字节材料 XOR `so@0xC2960` 常量
    = `aa3d0ac931aec5f251c7b709f8d36c97`（**静态硬编码**）；
  - `N != 0` 分支（0x470E8/0x471F4）仍是同一套 S 盒/KSA，只是按 `0x20000`
    处理文件偏移分块（`x0 >> 17` 判断），不是另一套算法。
- 路径行：无前缀 = 应用（加密）；`!` 前缀 = 排除。
  so 内默认排除项：`!/**/`（0xC3AF8）、`!/sdcard/`（0xC3AFE）。
- 匹配/应用：`0x46FCC` 对命中文件执行 `open→read→sub_470C0(enc_type)→write`
  （阈值判断见 0x464D4/0x468EC 等处的规则遍历：以 `!` 开头的条目直接跳过）。

### 42.4 规则来源 **[静态]**

`sub_3185C` 在调用 `sub_41F80` 前构造配置结构：
- 从 APK 取 `assets/RES_RULE`（`sub_46188(apkPath,&len,"assets/RES_RULE",0)`）；
- 用 **`"KEY_RES_ENC"`（11 B，so@0xC60E1）重复异或** 解密；
- 结构：`+0x0C` 长度、`+0x10` 缓冲、`+0x18` 标志、`+0x1C` 条数、`+0x20` 规则串；
- 作为第 5 个参数传入 `sub_41F80`。

**注意**：当前 APK（`base.apk`）的 `assets/` 中 **没有 `RES_RULE`**（已用设备 `unzip -l`
穷举确认），因此这次调用传入的是空规则；设备上 .edata 的两条规则是**历史/服务端配置残留**，
壳在 `a3==0` 时只解析并刷新它，不会清空。

### 42.5 与其它状态文件的关系

| 文件 | 作用 | 谁维护 |
|---|---|---|
| `classes.jar` | 加密 DEX 容器（§39） | 壳 |
| `classes.dve` | 构建/缓存版本戳，驱动 `.edata` 重建（§40） | 壳 |
| `.edata` | 文件加密策略：enc_type + 路径规则（本节） | 壳 |
| `info.y` | 反注入/反脱壳检测规则库（§41） | 壳 |

### 42.6 安全含义

- `enc_type/0` 的 RC4 密钥是 **so 内静态常量异或**，不随设备/账号变化 → 数据文件加密可离线还原；
- 规则只决定「哪些路径加密」，不构成密码学强度；
- `.edata` 本身可被删除（壳会重建）或按规则篡改（影响哪些文件被加密/解密，可能造成数据不可读），
  但它与 DEX 解密、`classes.jar` 解包无关。

---

## 43. RC4 文件加密验证（enc_type/0）（2026-11-11）

### 43.1 结论（已验证）

- `enc_type/0` 的透明文件加密是 **标准 RC4**（KSA + PRGA，16 字节密钥）；
- 密钥 = `so@0xEADF8`（16 B）XOR `so@0xC2960`（16 B）
  = `aa3d0ac931aec5f251c7b709f8d36c97`（静态，和设备/账号无关）；
- 对设备上 `shared_prefs/*.xml` 实测：**5/5 解密成功**，全部得到合法可解析 XML；
- 排除规则生效：`databases/*.db` 保持明文 `SQLite format 3`；
- 重新加密可逐字节还原原文件（RC4 对称）。

### 43.2 密钥流比对 **[验证]**

设备文件 `shared_prefs/ALITX_LOGGER_DATA.xml` 的密文头与标准 SP XML 头异或得到密钥流，
与本地 `RC4(aa3d…c97)` 输出逐字节相同：

```
file : ce b3 96 54 c8 c5 1a 68 87 42 0b 5a 59 e3 9b ce ...
rc4  : ce b3 96 54 c8 c5 1a 68 87 42 0b 5a 59 e3 9b ce ...
match: True（前 56 B 全等，覆盖完整 XML 头）
```

设备上不同时间写入的文件（10-27 旧文件、11-11 当天新写的 `AUTH_APP_INFO.xml`）
密文前缀完全一致 → 固定密钥、无 per-file IV、始终从偏移 0 起加密。

### 43.3 算法细节（sub_470C0，0x470C0–0x47468）**[静态]**

- 字节 0–255 身份表从 `0xC60EC` 拷贝到栈（`00 01 02 … FF`）；
- **KSA**：`i=0..255`，`j=(j+S[i]+key[i%16])&0xFF`，`swap(S[i],S[j])`
  （i=0 被展开，`j=key[0]`，因 `S[0]=0` 等价于标准 swap）；
- **PRGA**：`i=(i+1)&0xFF; j=(j+S[i])&0xFF; swap; out ^= S[(S[i]+S[j])&0xFF]`；
- 参数：`x0=文件偏移`（先空转 x0 字节密钥流），`x1=缓冲`，`x2=长度`；
- `enc_type==0` 一次处理整段；`enc_type!=0` 走 0x471F4 分块路径（每块 ≤0x20000），
  算法相同；偏移 ≥0x20000 的块在 0x473D0 处退化为 `XOR 0xAC`。

### 43.4 覆盖范围 **[观测]**

| 路径 | 状态 | 证据 |
|---|---|---|
| `shared_prefs/*.xml` | RC4 加密 | 5 个文件（含当天新写）均解密为合法 XML |
| `databases/*.db` | 明文 SQLite | 头部 `SQLite format 3\0` |
| `!databases/nebula_app.db` | 排除 | 同上，规则语义为 `!` 前缀跳过 |

### 43.5 复现工具

`analysis/tools/dve_rc4.py`（从 so 自动推导密钥）：

```
python3 -I analysis/tools/dve_rc4.py libDexHelper.dec.so in.bin out.bin
key=aa3d0ac931aec5f251c7b709f8d36c97 ...
```

实测：解密 221 B 的 SP 文件 → 合法 XML；再加密 → 与原密文 `cmp` 一致（ROUNDTRIP OK）。

### 43.6 安全含义

- 密钥静态硬编码在 .so（两段常量异或），与 DEX 密钥（常量 ⊕ 包名，§39）同属
  “静态可推导”级别：拿到 .so 即可离线解密全部命中文件；
- RC4 本身为已知弱流密码（无 IV、密钥重用、首字节偏差），加密强度有限；
- 与 `classes.jar` DEX 解密无交集：这里是**应用数据文件**层的透明加解密。

---

## 44. `enc_type != 0` 分支验证（2026-11-11）

### 44.1 结论（Unicorn 模拟验证）

用 Unicorn 直接执行 `sub_470C0`（`analysis/tools/unicorn_dve.py`），6/6 用例与模型一致：

| 分支语义 | 验证结果 |
|---|---|
| `enc_type == 0` | 整段 RC4（密钥流偏移 = x0） | ✓ |
| `enc_type != 0`，`offset < 0x20000` | `chunk = min(0x20000 - offset, size)`：前 chunk 字节 RC4（从密钥流 offset 起），**其余字节 XOR 0xAC** | ✓ |
| `enc_type != 0`，`offset >= 0x20000` | 整段 **XOR 0xAC**（不进 RC4） | ✓ |

模拟用例（pattern 数据，直接读回 buffer 比对）：

```
type0  off0     size=0x21000 match=True
type0  off1000  size=0x2000  match=True
type16 off0     size=0x21000 match=True   # 0x20000 RC4 + 0x1000 XOR 0xAC
type16 off1000  size=0x40000 match=True   # 0x1F000 RC4 + 0x21000 XOR 0xAC
type16 off20000 size=0x1000  match=True   # 全 XOR 0xAC
type16 small    size=0x100   match=True   # 纯 RC4
verified 6/6
```

### 44.2 代码路径 **[静态]**

```
0x470E4  cbz w9, 0x47100          ; enc_type==0 -> 整段 RC4
0x470E8  lsr x9, x0, #0x11        ; offset < 0x20000 ?
0x470EC  cbz x9, 0x471F4          ;   是 -> 分块 RC4 路径
0x470F0  w9 = 0; -> 0x473D0       ;   否 -> 整段 XOR 0xAC
0x471F4  chunk = min(0x20000-off, size); size -= chunk
0x47210  KSA（与 type 0 相同）
0x472BC  跳过 offset 字节密钥流
0x47374  PRGA 加密 chunk
0x473C8  剩余 size 字节 -> 0x473D0 逐字节/向量 XOR 0xAC
```

### 44.3 真实调用点（偏移参数）**[静态]**

`sub_470C0` 共 6 个调用点：

| 调用点 | 偏移参数 | 场景 |
|---|---|---|
| 0x47058 | `x0=0` | 文件整体读写后的转换（`sub_46FCC`：open→read→transform→write） |
| 0x49BBC | `x0=x20`（变量） | 读写 hook 路径 |
| 0x4A3BC | `x0=x19`（变量） | 读写 hook 路径（长度 `min(x25-x19,x22)`） |
| 0x4AAA8 | `x0=w20` | 读写 hook 路径 |
| 0x4AB88 | `x0=x19` | 读写 hook 路径 |
| 0x4B090 | `x0=x19` | 读写 hook 路径 |

即：非 0 偏移分支会在 **pread/pwrite 类局部读写的 hook** 中实际使用，
`offset >= 0x20000` 的简化处理正是为“大文件尾部/随机偏移读”准备的。

### 44.4 现状说明

当前设备 `.edata` 为 `enc_type/0`（§42/§43 已验证 shared_prefs 为整段 RC4），
因此 **type 16 分支在本次构建中未观察到真实样本**；其行为由上述模拟与静态路径确认。
若服务端下发 `enc_type/16`（经 `assets/RES_RULE` 或后续配置），
文件将表现为：前 0x20000 字节 RC4 密文，其后全部 `XOR 0xAC`。

### 44.5 工具

- `analysis/tools/unicorn_dve.py`：Unicorn 执行 `sub_470C0`，自动比对模型；
- `analysis/tools/dve_rc4.py`：type 0 的 RC4 文件解密/加密。

---

## 45. 总体进度汇总（截至 2026-11-11）

### 45.1 一句话状态

**核心链路已全部打通**：自解密/脱壳 → 通用 unpacker → DEX 动态捕获 → `classes.jar` 容器 →
标准 SM4 解密（14/14 复现）→ 三个状态文件（`classes.dve` / `info.y` / `.edata`）→
DVE 文件加密（RC4，实体验证）→ **`info.y` 完整还原为编译后的 YARA 规则集**
（消费链、规则内容、condition 字节码、引擎级命中验证全部完成）。
剩余项集中在**完整性校验、服务端配置与工程化**（见 §45.7），不影响已知功能还原。

### 45.2 已完成链路（按顺序）

| # | 环节 | 结论 | 章节 |
|---|---|---|---|
| 1 | ELF 结构 | 双份 `PT_DYNAMIC`（`p_offset` 诱饵 / `p_vaddr` 真表）；首段加密；真实符号 1508 条 | §2、§3、§12、§14 |
| 2 | 自解密引导 | DT_INIT 自行解压 LZSS 流 + 4 字节 XOR + 重定位 + icache flush；Unicorn 等价重放 | §16–§18 |
| 3 | 通用脱壳 | `unpack.py` 用 Unicorn 执行原 DT_INIT，输出与 3 路独立方法逐字节一致；多 so 验证通过 | §17–§19 |
| 4 | JNI/ART | `JNI_OnLoad`、ART 符号解析、`VerifyClass` 篡改与 Runtime 标志清零 | §13、§20 |
| 5 | DEX 动态捕获 | libdexfile 打开点抓取；42 个 DEX，21 个与 FART 一致（含全部 14 个业务 DEX） | §21–§27 |
| 6 | 容器格式 | `classes.jar` = 伪 DEX 头 + `dexdata0`（`0x27BC0`）；`0x1000` 段头 + 14 条记录表 | §28–§33、§39.6 |
| 7 | MD5 | `sub_457A4` 就是标准 MD5 压缩（逐字节一致），`sub_45374` 为 update/final | §34–§37 |
| 8 | **DEX 解密** | **标准 SM4-ECB**；密钥 = so 常量 `0xC2A50` ⊕ 包名；仅前 `0x20000` 加密、其余明文；14/14 DEX MD5 与动态捕获一致 | §39 |
| 9 | `classes.dve` | 24 B 版本/缓存戳（`vtag`）：`MD5(so@0xEAC90 64B)` + `fstat(oat).st_ctim`；状态 0/1/2 → `sub_41F80` | §40 |
| 10 | `info.y` | **编译后的 YARA 规则集**（`INFO-` 容器：12 段 + 214 条 arena 重定位）；9 规则/21 字符串；APK `assets/info.y` → `.cache/info.y` | §41、§46、§51–§55 |
| 11 | `.edata` | 透明文件加密（DVE）策略：`enc_type/N` + 路径规则（`!`=排除）；启动解析、版本变化时重写 | §42 |
| 12 | DVE 加密验证 | `enc_type/0` = **标准 RC4**，密钥 `aa3d0ac931aec5f251c7b709f8d36c97`；5 个真实 XML 解密成功 | §43 |
| 13 | `enc_type != 0` | 前 `0x20000` RC4 + 其余 `XOR 0xAC`；`offset≥0x20000` 全 `XOR 0xAC`；Unicorn 6/6 | §44 |
| 14 | `info.y` 消费链 | 释放(`sub_4B4F0`) → 入口(`sub_4E9F0`) → wrapper `0x99A7C`（get_hash + fopen）→ parser `0x7D924` → 规则对象 → maps 扫描 | §46 |
| 15 | YARA 引擎识别 | 扫描器为静态链接的 **YARA**（`_yr_scanner_scan_mem`、`yr_modules_table`、`elf__*`、`rb_null`） | §47 |
| 16 | 扫描对象定性 | `sub_85128` = open+fstat+malloc+read **整文件内容**（非 mmap、非 ELF 解析），`madvise(SEQUENTIAL)` | §48 |
| 17 | 规则热更新接口 | JNI `com.secneo.apkwrapper.H.sn(String)` 校验 INFO 后覆盖 `.cache/info.y`（静态代码中未被调用） | §49 |
| 18 | `get_hash` 验证 | 标准 MD5，范围 = `info.y[0x16:]`；`0x99E80` 压缩函数 Unicorn 8/8 | §50 |
| 19 | `info.y` 格式/规则/条件 | 12 个 arena section + **214 条 `yr_arena_ref_to_ptr` 重定位**；9 条规则/21 字符串；condition 真值表还原 | §51–§55 |
| 20 | 规则实际扫描与引擎验证 | 设备 56 库 0 命中；14 个测试 so 引擎级 **14/14** 一致；hex 标记为**字面量** | §56–§59 |
| 21 | 自毁原语 | `0x384F0` = **裸 `kill(pid, SIGKILL)`**（`x8=129`，无 libc 导入）；7 处 `bl` + 9 处内联 `svc`（`kill`/`getpid`/`read`）；反调试子进程（fork/pipe/`/proc` 扫描）异常即自杀 | §61 |
| 22 | x86_64 变体 | 双 `PT_DYNAMIC`（真表在 `p_vaddr=0x111498`）；`DT_INIT` 原地解压首段（0x61A85→**0xE1078**）；`unpack_x86.py` 保真 0 差异；1520 符号；SM4/RC4/密钥与 arm64 同值 | §62 |
| 23 | x86 `JNI_OnLoad` | `0x319F0`/0x2535；注册 `H`（4 个）与 `AW`（2 个）native；SDK 23–30 跳表；sourceDir/dataDir/classes.jar 路径与 mkdir；`sub_3BD60` maps+binder 定位 libart；`sub_33F30` DVE/SharedPreferences 初始化 | §63 |
| 24 | 功能点清单 | 7 个能力域、**50 条功能点**（F-01…F-73），含入口/行为/开关/证据 | §65 |
| 25 | x86 `sub_33F30` | `0x33F30–0x35746`：vtag/`classes.dve`、`RES_RULE`/`.edata`、SharedPreferences 强制加载、反调试看门狗（fork/pipe/ptrace）、`nop` native | §66 |

### 45.3 关键参数速查

| 项 | 值 |
|---|---|
| 静态样本 SHA-256 | `d7455105a14ae87bc76e3f5db04e5bdcfd1f4fa7b5949d4a8f49ed623fc4ebdd`（979,501 B） |
| 解密重建镜像 | `libDexHelper.dec.so`（SHA-256 `c37fabca…6523`） |
| DEX 容器 | `classes.jar`：伪 DEX 头 + `dexdata0`@`0x27BC0`；记录表 @`dexdata0+0x1000-14*16`（`0x28AE0`） |
| 记录格式 | `{u32be offset, u32be size, 8B 0}`，14 条（0…13） |
| 条目存储 | `dexdata0+0x1000+offset`；**前 `0x20000` 字节 SM4 密文，其余明文** |
| SM4 密钥 | `so@0xC2A50`(16B) XOR 包名 `com.example.reference`[:16] = `<redacted-derived-key>` |
| SM4 参数 | 32 轮 T 表；T0@`0xC5CE0`、TBOX0/1/2@`0xEA000/0xEA400/0xEA800`（与公开常量 0/256 差异） |
| `vtag` | so@`0xEAC90`，64 B；`classes.dve` = `MD5(vtag)` 16 B + `fstat().st_ctim` 8 B |
| `info.y` | `INFO-` + `MD5(body[0x16:])` + count(1B, 本文件 12) + 12×`{u32 offset, u32 flags, u32 size}` + 尾部 **214×`{u32 section, u32 offset}` 重定位** |
| `info.y` 规则 | 9 rules / 21 strings / namespace "default"；8 条 AND 链，yarfahook = `(s7∧s8)∨(s9∧s10)` |
| hex 标记 | `0x12345678` / `0x23456789` 是**字面量模式字节**（非通配，引擎验证） |
| YARA VM | 执行器 `0x81DFC`；分派表 `0xC9CA4`（handler=`0x81F20+off*4`）；栈 count@sp+0x38/base@sp+0x40；未定义哨兵 `0xFFFABADAFABADAFF` |
| YARA ctx | `+0x20/+0x28` 用户数据/回调（0x4F414）、`+0x10` flags=0x18、`+0x18` 超时、`+0x90/0x98` match 表 |
| 引擎复现要点 | 重定位 1024–1027 + **257(ABS64)**；**0x2B390 = calloc**（非 malloc）；init `0xA0E7C` |
| `.edata` | 行 1 `enc_type/<N>`，其余行为路径规则；`!`=排除 |
| DVE RC4 密钥 | `so@0xEADF8` XOR `so@0xC2960` = `aa3d0ac931aec5f251c7b709f8d36c97` |
| DVE type≠0 | 前 `0x20000` RC4（密钥流按偏移跳过），其余 `XOR 0xAC`；偏移 ≥`0x20000` 全 `XOR 0xAC` |

### 45.4 工具与产物索引

| 工具 | 作用 |
|---|---|
| `analysis/tools/unpack.py` | 通用 Unicorn 脱壳（执行原 DT_INIT） |
| `analysis/tools/unpack_x86.py` | x86_64 变体脱壳（真 dynamic + DT_INIT + syscall 钩子） |
| `analysis/tools/lzss_decode.py` | `sub_108914` LZSS 解压器的忠实移植（0/756480 差异） |
| `analysis/tools/sm4.py` | 纯标准 SM4（国标测试向量通过） |
| `analysis/tools/fdex_unpack.py` | `classes.jar` → 14 个 DEX（14/14 复现） |
| `analysis/tools/dve_rc4.py` | DVE `enc_type/0` 文件加解密（自动推导密钥） |
| `analysis/tools/unicorn_dve.py` | Unicorn 执行 `sub_470C0`，验证两种 `enc_type` 分支（6/6） |
| `analysis/tools/unicorn_hash.py` | Unicorn 模拟 `sub_457A4/sub_45374`（MD5 等价验证） |
| `analysis/tools/ida_force_dump.py` | 强制建函数 + 伪代码导出（1,955 函数） |
| `analysis/tools/rename_imports.py` | 真动态表 → 导入桩重命名 |
| `analysis/tools/ida_retype_dump.py` | libc 原型 + 重命名 + 反编译 |
| `scripts/capture_dex.js` / `scripts/run_capture.py` | 动态 DEX 捕获 |
| `analysis/tools/parse_info_y.py` | `info.y` 解析：12 段 + 214 条重定位 + 哨兵校验 |
| `analysis/tools/emu_info_y.py` | Unicorn 执行 parser `0x7D924`（伪造 I/O + 重定位） |
| `analysis/tools/emu_rule_obj.py` | 构建/验证 0x50 规则对象（15/15） |
| `analysis/tools/yara_dump.py` | 还原 `.yar` 源码（9 规则/21 字符串） |
| `analysis/tools/cond_dump.py` | condition 字节码线性反汇编 |
| `analysis/tools/cond_vm.py` | condition VM 执行 + 真值表 |
| `analysis/tools/scan_rules.py` | 用还原规则扫目录（精确匹配） |
| `analysis/tools/emu_yara_scan.py` | Unicorn 跑壳 YARA 引擎（init + scan，14/14） |

| 产物 | 路径 |
|---|---|
| 解密镜像 | `analysis/libDexHelper/libDexHelper.dec.so` |
| 伪代码 | `analysis/libDexHelper/ida_force/functions/*.c`、`renamed/*.c`、`retyped/*.c` |
| 动态 DEX | `analysis/dexcap_dynamic/`（42 个，index.json） |
| 容器/样本 | `/tmp/classes.jar`、`/tmp/dexdata0.bin`、`/tmp/info.y`、`/tmp/blks/dexcap/` |
| 复现输出 | `/tmp/fdex_out/`（14 个 DEX，MD5 全部命中） |
| 测试 so | `/tmp/testlibs/`（14 个 AArch64 测试对象，引擎/模型共用） |
| 设备库 | `/tmp/dev_libs/arm64/`（56 个业务 .so，99 MB） |
| 规则源码 | `/tmp/info_y_recovered.yar`（9 规则/21 字符串） |

### 45.5 验证矩阵

| 项 | 验证方式 | 结果 |
|---|---|---|
| 自解密 | Unicorn / 静态移植 / 运行时镜像 三路 | 逐字节一致 |
| LZSS | 移植实现 vs 原函数输出 | 0/756,480 差异 |
| MD5 | 国标向量 + Unicorn | `d41d8cd9…` 一致 |
| DEX 解密 | 14 个条目 vs 动态捕获 | **14/14 MD5 一致**，adler32 通过 |
| SM4 | 国标测试向量 | `681edf34…` 通过 |
| `classes.dve` | 静态 + 设备观测 | 结构/时间线吻合 |
| `info.y` | 字符串/结构 + APK 资源比对 | 与 `assets/info.y` 逐字节相同 |
| DVE type 0 | 5 个真实 `shared_prefs/*.xml` | 全部解密为合法 XML，roundtrip 一致 |
| DVE 排除规则 | `databases/*.db` | 明文 SQLite，规则生效 |
| DVE type≠0 | Unicorn 6 用例 | 6/6 与模型一致 |
| `info.y` 解析模拟 | Unicorn parser `0x7D924` vs Python 模型 | 12 段内容 10/10 一致，214 重定位全有效 |
| 0x50 规则对象 | getter 结果 + 段内容比对 | **15/15** |
| 条件字节码 | Python VM 真值表 | 9 条规则条件全部还原 |
| 规则内容 | `yara_dump.py` vs 对象计数 | 9 rules / 21 strings / 1 namespace |
| 设备扫描 | 56 个业务 .so + 系统库目录 | **0/9 命中**（仅 `Unpacker` 在 XzUnpacker_* 中，规则不成立） |
| 测试 so（模型） | `scan_rules.py` 精确匹配 | 正例全中、反例全不中 |
| 壳引擎扫描 | Unicorn 引擎 vs 期望 | **14/14 一致**，无假阳、无崩溃 |

### 45.6 更正记录（本文早期结论）

1. §38.3「自定义解压器」**作废** → §39：实际是标准 SM4-ECB + 前 `0x20000` 部分加密。
2. 早期「修改版 MD5」**作废** → §36：标准 MD5。
3. 早期把 `0xC60E0/0xC64E0/0xC68E0` 当作 SM4 T1/T2/T3 **作废**：该区实为
   `"KEY_RES_ENC"`（`0xC60E1`）与身份 S 盒（`0xC60EC`）；真正的 TBOX0/1/2 在
   `0xEA000/0xEA400/0xEA800`，且与公开 SM4 表完全一致。
4. 「密钥白盒化」**不成立**（§39.8）：表为公开常量、轮密钥明文、密钥静态可推导。
5. §41 对 `info.y` 的「166 条目」描述**修正** → §51：实际是 12 个 arena section +
   214 条 `yr_arena_ref_to_ptr` 重定位（166 是 body 开头 u32 的误读）。
6. 「hex 标记 `12345678/23456789` 是通配」**作废** → §59：引擎验证为**字面量**。
7. §58 的「引擎模拟存在 artifact（误报/崩溃）」**作废** → §59：根因是
   `0x2B390` 被当作 malloc 而非 **calloc**，修复后引擎 14/14 全保真。

### 45.7 未完成 / 下一步

1. **检测命中后的处置链**：规则命中经回调 `0x4F414`（mode 1/2/3）之后的**上报**已还原（§60）；
   硬终止原语已定位为裸 `kill(pid, SIGKILL)`（§61）及其 7 处调用/9 处内联变体。
   仍缺：`config+0x14C` 位掩码的**运行时默认值**（决定哪些分支自毁 vs 仅上报），
   以及 `0x2DBC0` 文件型上报后是否有服务端二次拉取。
2. **完整性校验路径**：`manifest.mf` / `rsa.sig` 是否在 so 内校验、失败行为。
3. **服务端配置**：当前 APK 无 `assets/RES_RULE`，`enc_type/16` 的下发与生效条件未实测。
4. **真实 type≠0 样本**：需要服务端配置才能观测（当前设备为 `enc_type/0`）。
5. ~~**x86_64 变体**：`libDexHelper-x86.so` 的 unpack 尚未适配。~~
   **已解决（§62）**：`unpack_x86.py` 完整解包，解压区与手工模拟 0 差异；
   符号/SM4/RC4/密钥与 arm64 对齐。
   **`JNI_OnLoad` 已审计（§63）**：注册 H/AW natives、SDK 23–30 分派、
   路径/DVE/SharedPreferences 初始化。`H.d` 字符串解密器已完整还原（§64）。
   `sub_33F30` 已审计（§66）：vtag/`classes.dve`、`RES_RULE`/`.edata`、
   SharedPreferences 强制加载、反调试看门狗与 `nop` native。
   剩余：`load/load23` 逐函数语义、实机验证。
6. **工程化**：REA 的 IDA/jadx provider 配置已写入但需重启生效；`README_bypass.md` 已过期。
7. ~~`info.y` 消费链 / 规则解析入口~~ **已解决**（§46–§59）：规则为编译后 YARA，
   消费链、规则内容、condition、引擎级命中均已还原并验证。

### 45.8 复现入口（命令）

```bash
# 1) 通用脱壳
python3 -I analysis/tools/unpack.py analysis/libDexHelper/libDexHelper.so -o /tmp/dec.so --verbose

# 2) classes.jar -> 14 DEX（需设备上的 classes.jar）
python3 -I analysis/tools/fdex_unpack.py /tmp/classes.jar \
    analysis/libDexHelper/libDexHelper.dec.so com.example.reference /tmp/fdex_out

# 3) DVE 文件解密（enc_type/0）
python3 -I analysis/tools/dve_rc4.py analysis/libDexHelper/libDexHelper.dec.so enc.xml dec.xml

# 4) enc_type 分支模拟验证
python3 -I analysis/tools/unicorn_dve.py

# 5) info.y 解析 + 重定位校验（12 段 / 214 条）
python3 -I analysis/tools/parse_info_y.py /tmp/info.y

# 6) 还原 YARA 规则源码（9 规则 / 21 字符串）
python3 -I analysis/tools/yara_dump.py /tmp/info.y

# 7) 用还原规则扫目录（模型）
python3 -I analysis/tools/scan_rules.py /tmp/info.y /tmp/testlibs --verbose

# 8) 用壳的 YARA 引擎扫（Unicorn 全保真）
python3 -I analysis/tools/emu_yara_scan.py /tmp/info.y /tmp/testlibs/libtest10.so
```

---

## 46. `info.y` 的消费链：释放 → 解析 → 规则对象 → maps 扫描（2026-11-11）

### 46.1 结论（消费链已定位）

```
sub_4B4F0 (JNI 守护线程)
  ├─ sub_46188(apkPath, …, "assets/info.y", 0)      从 APK 取资源
  ├─ open(".cache/info.y", 0x242, 0666) + write     落盘
  └─ 循环: sub_4E9F0(path)                            ← 真正消费入口
        ├─ wrapper 0x99A7C(path, &out)   [经 PLT 0x2B930 / GOT 0xE8F98]
        │    ├─ get_hash(path, &hash)     0x991F0（0x88C 字节哈希实现）
        │    ├─ fopen(path, "rb")
        │    ├─ parser 0x7D924({FILE*,fread}, &out, &hash)
        │    │     [经 PLT 0x2BFD0 / GOT 0xE92E8；符号 idx 1414 GLOBAL FUNC, size 0x474]
        │    │     校验 "INFO-"，header[21] 记录长度 ≤16，
        │    │     memcmp(header[5:21], get_hash(path), 16) 完整性校验
        │    │     malloc(0x1A0) 规则表：refcount、记录长度、0x100000 上限、条目数组
        │    ├─ builder 0x9907C(table, &out)   生成 0x50 字节规则对象
        │    └─ dtor 0x7D0F4(table)            refcount-1 / 释放条目与链表
        └─ 成功后: time() → 互斥锁 → openat("/proc/self/maps")
             → 逐行 sscanf 解析映射 → 用规则做反注入/反脱壳检测
             → 结束时释放规则对象（0x4F3FC）
```

另一个包装调用点在 `0x4B630`（同一 wrapper，路径由运行时字符串拼接），属于同一套 INFO 文件加载逻辑。

### 46.2 为什么此前找不到调用者

- 解析器与包装函数都是 **导出符号**（`st_info=0x12` = GLOBAL FUNC），内部调用全部走
  **PLT/GOT 间接调用**，没有 `bl 0x7D924` 这样的直接 xref：
  - parser：PLT stub `0x2BFD0`，GOT `0xE92E8`（`.rela.plt` 项 `0x29180`，符号 idx 1414）；
  - wrapper：PLT stub `0x2B930`，GOT `0xE8F98`（符号 idx 1148，size 0xC4）。
- 解析器还把 libc `fread` 的函数指针（GOT `0xE9CC8`，符号 `fread`）放进结构体传入，
  进一步规避静态引用。

### 46.3 解析器（0x7D924，size 0x474）行为 **[静态]**

- `fread(buf, 0x16, 1, fp)` 读 22 字节头：
  - `buf[0:5]  == "INFO-"`
  - `buf[21]  = 记录长度`（本文件为 `0x0C`，要求 ≤16）
  - `memcmp(buf+5, hash16, 16)` —— 头部摘要必须等于 `get_hash(path)`；
- 随后 `fread(rec, 0x0C, 1, fp)`，`malloc(0x1A0)` 建表：
  - `[0x00]=refcount(1)`、`[0x04]=记录数/长度`、`[0x188]=0x100000`
  - 条目按 0x18 步长存放，逐条 `fread` 数据块（`sub_2C570`，经结构体里的 `fread` 指针）
  - 偏移 `+0x190` 处挂着一条释放链表；
- 返回值：0 成功；非 0 为错误码（6/8 等），失败时包装函数调用清理函数。

### 46.4 规则对象（0x9907C，size 0x108）

把解析表按索引取出并组装成 **0x50 字节对象**：

| 对象偏移 | 取自表索引 |
|---|---|
| +0x00 | 表本身 |
| +0x08 | 1 |
| +0x10 | 3 |
| +0x18 | 4 |
| +0x20 | 8 |
| +0x28 | 10 |
| +0x30 | 9 |
| +0x38 | 6 |
| +0x40 / +0x48 | 表头拷贝 |

即 info.y 解析后并不是“字符串列表”，而是 **按索引分节的二进制规则结构**（11 节），
由该对象提供给检测逻辑使用。

### 46.5 与 §41 的关系（补全）

§41 只确认了 info.y 的**内容与释放**；本节补上了**读取与解析**：
`sub_4E9F0` 是消费入口，`0x99A7C → 0x7D924 → 0x9907C` 是读取/校验/建模路径，
解析成功后立刻进行 `/proc/self/maps` 扫描，说明 info.y 的规则用于运行时映射/注入检测。

### 46.6 仍有待确认

1. 0x50 规则对象的各节如何具体参与 maps 匹配（扫描循环中对对象的实际引用点仍需细跟）；
2. `0x4B630` 调用点所加载的“另一个 INFO 文件”路径（运行时字符串拼接，尚未还原）；
3. `get_hash`（0x991F0）是否为标准 MD5 / 自定义变体（头部摘要实测等于 `MD5(info.y[0x16:])`，
   高度指向“对 body 做 MD5”，但未逐指令确认）。

---

## 47. 0x50 规则对象在 maps 扫描中的引用链（YARA 引擎）（2026-11-11）

### 47.1 结论

- `info.y` 解析出的 **0x50 字节对象 = YARA 规则句柄**（refcount + 规则链表 + 各节索引）；
- 该对象被放进 worker 上下文：`ctx+0x30 = object`；
- maps 扫描收集到的每个 `.so` 映射路径，最终交给 **YARA 扫描器**：
  `matcher 0x9C024 → _yr_scanner_scan_mem (0x9BF94 → 0x9B8C8)`；
- 即：`info.y` 是 **编译后的 YARA 规则集**（自定义 `INFO-` 容器包装），
  壳内静态链接了 YARA 引擎（含 ELF 模块），用于扫描已加载库中的注入/脱壳特征。

### 47.2 主流程中的引用点（0x4E9F0 / sub_4EA10）

```
0x4EA24  [sp+0x28] = 0
0x4EA4C  wrapper 0x99A7C(path, &sp+0x28)     ← 解析 info.y，出参=规则对象
0x4EA7C  ring_cnt(0xE9E98)=0, ring_idx(0xE9F98)=0   ← 清空扫描结果环
0x4EB04  openat("/proc/self/maps")
0x4EB8C+ sscanf("%lx-%lx %c%*c%c%*c %*s %*s %*d%1023[^\n]") 逐行解析
         → 结果写入全局环（array 0xE9EC0 / cnt 0xE9E98 / idx 0xE9F98，容量 0x800）
0x4F328  x0 = [sp+0x28]（规则对象），x1 = &ctx_slot
0x4F33C  sub_9B528(object, &ctx_slot)        ← 用规则对象构建 worker ctx
0x4F378  pthread_create(&tid, NULL, 0x4F680, &ctx_slot)
         之后 pthread_join
```

`0x9B528`（ctx 构建）关键写入：

| ctx 偏移 | 内容 |
|---|---|
| +0x00 | magic `0xDAFF…FABA…BADA…FFFA`（16 B） |
| +0x10 / +0x14 | 0x18 / `time(0)` |
| **+0x30** | **规则对象指针** |
| +0x48 | 互斥锁（pthread_mutex_init） |
| +0x80 / +0x88 | 按对象 +0x40 / +0x48 字段 `>>6 +1` 分配的缓冲 |
| +0x90 / +0x98 | 按对象 +0x44 字段 `*0x18` 分配的两块缓冲 |

随后遍历 **对象 +0x18 的链表**，对每个条目：
`sub_8FDD4(entry,&size)` → `sub_89F30(dst, entry+0x10, size, 0)` → `sub_8F9FC(buf, ctx+0x14)`
（把规则/字符串从对象展开进 ctx 缓冲，并以时间做一次变换/散列）。

### 47.3 worker 线程（入口 0x4F680，同一函数体的二级入口）

```
pop ring: idx=0xE9F98, cnt=0xE9E98, arr=0xE9EC0, 环绕 mod 0x800
         → x20 = 映射路径
path 以 "s"/"so" 结尾检查（0xC3F7A = "so"）       ← 只处理 .so 映射
剩余时间窗 = 0xF4240 - difftime(now, ctx_slot+0x18)
sub_9B724(ctx, 剩余时间)                          ← 设置扫描超时/预算
sub_9C024(ctx, path)                              ← 匹配入口
命中时: 加锁 0xE9CA8，fprintf("error scanning %s: ", path) …
```

### 47.4 匹配入口与 YARA

```
0x9C024(ctx, path)
  ├─ sub_85128(path, &out)          打开并**把整个 .so 文件读入堆缓冲**（§48，不是 mmap/ELF 解析）
  └─ blr *(0xE9D28)                 ← GOT GLOB_DAT，符号 idx 771
        = _yr_scanner_scan_mem (0xEDFF0 → RELATIVE → 0x9BF94)
           0x9BF94 组装 {data,len,callbacks} → sub_9B8C8（0x4EC，真正扫描实现）
```

符号证据（dynsym，均为 GLOBAL，名字未混淆）：

| 符号 | 值 | 含义 |
|---|---|---|
| `_yr_scanner_scan_mem` | 0xEDFF0 | YARA 扫描器 API 指针 |
| `yr_modules_table` | 0xEDFC0 | YARA 模块表（含 ELF） |
| `yr_lowercase` / `yr_altercase` | 0x106FFC / 0x106EF8 | YARA 字符串变换表 |
| `elf__load` / `elf__initialize` / `elf__finalize` / `elf__declarations` | 0xA0600 / … | YARA ELF 模块 |
| `rb_null` | 0xEDFF8 | YARA rule-base 空节点 |
| `yr_trycatch_trampoline_tls` / `yr_yyfatal_trampoline_tls` | 0x106EF4 / 0x106FF8 | YARA 解析器 trampoline |

### 47.5 对 §41 / §46 的修正

- §41 把 info.y 描述为“规则库”方向正确，但实现上是 **YARA 编译规则**；
- §46 的 0x50 对象不是通用“配置对象”，而是 **YARA 规则句柄**：
  +0x18 规则链表、+0x40/+0x44/+0x48 各表长度、+0x188 容量上限、`INFO-` 头 + 摘要用于
  防止规则文件被替换；
- 检测目标（frida/xposed/taichi/youpk/fupk3/fart/yarfahook 等字符串）就是 YARA 规则里的
  字符串模式，扫描对象是 `/proc/self/maps` 中映射的 `.so`。

### 47.6 仍待确认

1. 规则对象 +0x18 链表节点与 YARA `YR_RULE` 的字段对应（parser 的记录布局 0x18 步长）；
2. ~~0x4B630 第二调用点加载的另一个 `INFO-` 文件路径~~ **已解决（见 §49）**：
   该处是 JNI 方法 `com.secneo.apkwrapper.H.sn(String)` 的实现——源路径由 Java 传入，
   目标固定为 `/data/data/%s/.cache/info.y`；
3. `sub_85128` 究竟是 ELF 模块加载还是 mmap 文件内容（影响“扫描文件还是映射内存”的精确表述）。

---

## 48. `sub_85128` 定性：整文件读入堆缓冲，非 mmap、非 ELF 解析（2026-11-11）

### 48.1 结论（已验证）

`sub_85128` 是 **“open + fstat + malloc + read 整文件”** 的辅助函数：

```
sub_85128(path, out):
  openat(AT_FDCWD, path, O_RDONLY)          ; 直接 svc #0，x8=56
  sub_85288(fd, 0, 0, out):
      fstat(fd, &st)                        ; 0x2B460 = fstat
      if (st_mode & 0xF000) == S_IFDIR: 返回 3   ; 拒绝目录
      size = st_size - offset                    ; offset 必须 1MB 对齐（此处 0）
      buf  = malloc(size)
      read(fd, buf, size)                   ; 直接 svc #0，x8=63
      out = { fd, size, buf }
      madvise(buf, size, 2)                 ; 0x2BD60 = madvise（MADV_SEQUENTIAL）
  close(fd)                                 ; 直接 svc #0，x8=57
```

- **不是 mmap**：没有 mmap 系统调用，缓冲区来自 `malloc` + `read`；
- **不是 ELF 解析**：没有读 `\x7fELF`、没有 section/program header 解析，
  只做 `open/stat/read`；库里的 `elf__*` 是静态链接 YARA 自带的 ELF 模块符号，
  本路径未启用；
- 读完后立即 `madvise(MADV_SEQUENTIAL)`，说明后续是按顺序整块扫描（YARA scan_mem）。

### 48.2 调用方如何使用（0x9C024）

```
0x9C024(ctx, path):
  sub_85128(path, &out)          ; out = { fd@+0, size@+8, buf@+0x10 }
  ldp x2, x1, [sp, #8]           ; x2 = size, x1 = buf
  x0 = ctx
  blr  *(0xE9D28)                ; _yr_scanner_scan_mem(ctx, buf, size)
  sub_853B4(&out)                ; 清理：free(buf) + close(fd)（0x2D030/0x2CB70）
```

`_yr_scanner_scan_mem`（0x9BF94）也印证这一点：它把 `{data=buf, len=size, 回调}`
组装成结构后调用 `0x9B8C8`，是典型的“扫描内存块”接口。

### 48.3 检测语义（重要）

- 扫描对象是 **`/proc/self/maps` 中列出的 `.so` 的磁盘文件内容**，不是进程内映射页；
- 对无路径/已删除/memfd 的映射，`openat` 会失败（返回错误码），不会被扫描；
- 因此该检测对“从文件加载的常见 Hook/脱壳库”有效（frida-agent、xposed、taichi、
  youpk、fupk3、fart 等特征串），但对 **动态生成、未落盘、或运行期改写的内存** 无效；
- 与 §43 的 RC4 文件加密链路无关：这里读的是 `openat` 原始文件内容，
  若目标文件受 DVE 加密，扫描看到的将是密文（检测逻辑对路径/特征的选择需要按此理解）。

### 48.4 补充

- `0x2B7A0`（0x853B4）确认是 out 结构析构：`free(out->buf)` + `close(out->fd)`；
- `0x2BD60 = madvise` 证明作者期待顺序访问整块缓冲区（性能优化，非加密/解析）。

---

## 49. `0x4B630` 的 INFO 文件路径：`com.secneo.apkwrapper.H.sn(String)`（2026-11-11）

### 49.1 结论

`0x4B630` 位于 **JNI 方法实现 `sub_4B4E0`**（IDA 把函数起点误标在 `0x4B4F0`，实际序言从
`0x4B4E0` 开始）。该方法在 `0x32BE0` 处通过 `RegisterNatives` 注册：

| 项 | 值 | 证据 |
|---|---|---|
| 类名 | `com/secneo/apkwrapper/H` | `0xC319B` |
| 方法名 | `sn` | `0xC3EB6` |
| 签名 | `(Ljava/lang/String;)I` | `0xC3166` |
| 实现 | `0x4B4E0` | `adrp+add` @`0x32BE4` |

**源路径由 Java 传入**（JNI `GetStringUTFChars`，`JNIEnv+0x548`），**不是固定字符串**；
目标路径固定为：

```
/data/data/%s/.cache/info.y          （%s = 包名，info+0x88）
```

即：Java 侧把某个 INFO 文件的路径交给 `H.sn(path)`，壳校验后**覆盖安装**到
`/data/data/<包名>/.cache/info.y`。

### 49.2 目标模板反混淆 **[静态 + 计算]**

代码（0x4B518–0x4B624）从 `.rodata` 取 16+16 字节，逐字节修正后作为 `snprintf` 的格式串：

```
rodata @0xC3EB9: "0fduc2ecwb1(t11dcfig2jpip0|"
- buf[0] = '/'                                     ; 0x2F
- buf[0x11..0x20] += 常量向量 @0xC28B0
  (fe fd ff fe fd ff fe fd ff fe fd ff fe fd ff fe)
- 末段逐字节减：0x21-3, 0x22-1, 0x23-2, 0x24-3, 0x25-1,
              0x26-2, 0x27-3, 0x28-1, 0x29-2, 0x2A-3
结果: "/data/data/%s/.cache/info.y"
```

### 49.3 函数行为（0x4B4E0）**[静态]**

```
x0 = GetStringUTFChars(env, jstring, 0)        ; 源路径
snprintf(dst, 0x200, "/data/data/%s/.cache/info.y", pkg)
wrapper 0x99A7C(src, &out)                     ; INFO 格式 + hash 校验
if (失败) return -1
fopen(src, "rb")  ; fopen(dst, "wb")
while (n = fread(buf, 1, 0x400, src)) fwrite(buf, 1, n, dst)
fclose ×2 ; return 0
```

即这是一个**带完整性校验的规则文件安装/热更新接口**。

### 49.4 调用者检索结果 **[静态，负结果]**

- 容器自带的 **stub DEX**（`classes.jar[0:0x27BC0]`，248 类）：
  - 修正 checksum/signature 后 jadx 可反编译，`H.java:381` 声明 `public static native int sn(String)`；
  - 自写 DEX 扫描器遍历全部 code_item（共 2066 条 invoke，含 0x6E–0x78/0xFA–0xFD），
    **未发现对 H.sn 的调用**；`map_list` 中没有 method_handle/call_site（排除 invoke-custom）；
- 14 个业务 DEX：没有 `com/secneo/apkwrapper` 类型/字符串（只有 `com/secneo/core/DexInstall`、
  `com/secneo/core/Helper`）；
- 设备上全部 `lib/arm64/*.so`：无 `apkwrapper` 字符串；
- 结论：该入口在本构建的**静态代码中未被调用**，可能用途：
  1. 服务端下发的动态策略/热更新（Java 侧动态代码或反射调用）；
  2. 为动态加载的插件 dex 预留；
  3. 本版本未启用的接口。

### 49.5 与 info.y 链路的闭环

| 路径 | 触发方 | 结果 |
|---|---|---|
| 静态释放 | `sub_4B4F0` 从 APK `assets/info.y` 提取 | 写入 `.cache/info.y`（§41） |
| **动态更新** | Java → `H.sn(path)` | 校验后覆盖 `.cache/info.y`（本节） |
| 消费 | `sub_4E9F0` 解析 + YARA 扫描 | §46/§47 |

两者共同维护同一个 `info.y` 规则库：APK 自带一份，运行期可由 Java 用新文件覆盖，
再交给 YARA 引擎扫描 `/proc/self/maps` 中的 `.so`。

---

## 50. `get_hash` 验证：标准 MD5（对文件体） （2026-11-11）

### 50.1 结论

`get_hash`（0x991F0，0x88C）就是 **标准 MD5**：

```
get_hash(path, out):
    fopen(path, "rb")
    fread(hdr, 0x16, 1, fp)              ; 跳过 INFO 头（22 B），丢弃
    ctx = {count=0, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476}
    while ((n = fread(buf, 1, 0x3E8, fp)) > 0):
        count += n*8; 每 64 B 调 0x99E80(ctx, block)
    标准 MD5 填充（0x80 + 0x00 + 64-bit LE 长度）→ 0x99E80 收尾
    *out = A||B||C||D（16 B，小端）
    fclose
```

即 **`get_hash(path) = MD5(file[0x16:])`**，与 info.y 头部 `[5:21]` 的校验字段一致
（§41 实测 `md5(info.y[0x16:]) == header[5:21]`）。

### 50.2 证据

**A. 压缩函数 0x99E80 是标准 MD5 压缩（Unicorn 逐字节验证）**

- K 常量逐项吻合：`0xd76aa478`、`0xe8c7b756`、`0x242070db`、`0xc1bdceee`、
  `0xf57c0faf`、`0x4787c62a`、`0xa8304613`、`0xfd469501`、`0x698098d8`、`0x8b44f7af`、
  `0xffff5bb1`、`0x895cd7be` …；
- F/G/H/I 四轮布尔函数与 `ror 25/20/15/10`（= rotl 7/12/17/22）完全一致；
- 用 Unicorn 直接执行 `0x99E80(state*, block*)`，与纯 Python 标准 MD5 压缩比对：

```
block 0 IV       OK      block 0 chained  OK
block 1 IV       OK      block 1 chained  OK
block 2 IV       OK      block 2 chained  OK
block 3 IV       OK      block 3 chained  OK
verified 8/8
```

工具：`analysis/tools/verify_gethash.py`。

**B. IV 与上下文布局**

```
q0 @0xCF5F0 = 00 00 00 00 00 00 00 00 01 23 45 67 89 ab cd ef
movk 拼出 0x1032547698badcfe
→ ctx: [0x40]=bitcount(u64), [0x48]=A, [0x4c]=B, [0x50]=C, [0x54]=D
```

**C. 收尾为标准 MD5**

- 0x99624：按 `(count>>3)&0x3f` 与 `0x38` 比较选择填充长度 `0x78/0x38`（标准 MD5 的
  “余数 < 56 补到 56，否则补到 120”）；
- 追加 `0x80` 后清 0，末 8 字节写 64 位小端长度；
- 最后 `0x99E80` 压缩一次，输出 `A||B||C||D` 小端 16 字节到 `*out`。

### 50.3 与其它 MD5 的关系

- 壳内还有已验证的标准 MD5：`sub_457A4`（压缩）+ `sub_45374`（update/final），
  用于 `vtag`/缓存戳（§36/§40）；
- `0x99E80` 是**同一算法的另一份内联实现**（大函数、完全展开，无 K 表数组），
  供 `get_hash` 做文件完整性校验；
- 因此 info.y 的完整性 = **`MD5(文件[0x16:])`**，可离线计算/伪造——即规则文件本身
  没有签名，只有摘要自校验（与 §47.6 的规则可替换性一致）。

---

## 51. 模拟解析 `info.y`（Unicorn 执行真实 parser + Python 模型复现）（2026-11-11）

### 51.1 结论

用 Unicorn 直接执行壳的 INFO 解析器 `0x7D924`（伪造 `fread`/malloc/realloc/memset/memcmp
并补齐 .rela 重定位），再用 Python 按还原出的格式独立解析，两者结果**逐字节一致**：

- 解析器返回 0，`fread` 位置 = `0x2572` = 文件长度 → **整个文件被消费**（含尾部重定位表）；
- 生成 12 个 section，尺寸与独立解析完全一致；
- 含重定位的 section 应用同一规则后 **10/10 内容一致**（4/5/8/9/11 无重定位，原始字节直接一致）。

### 51.2 已验证格式

```
+0x00  "INFO-"                 5 B
+0x05  MD5(body)              16 B   body = file[0x16:]
+0x15  record_count           1 B    ≤16（本文件 12）
+0x16  records[count]         12 B   {u32 offset, u32 flags, u32 size}
        sections                    按 offset 顺序连续；从 0xA6 至 0x1EC2
tail   relocations            8 B   {u32 section_idx, u32 offset}
```

- 12 条记录（offset 恰好等于各 section 的**绝对文件偏移**，首尾相接）：

| # | offset | size | 内容特征 |
|---|---|---|---|
| 0 | 0x0A6 | 16 | 计数/标志 |
| 1 | 0x0B6 | 480 | 指针表（含 -1 哨兵） |
| 2 | 0x296 | 0 | 空 |
| 3 | 0x296 | 1176 | 含 `FA DA BA FA…` 标记的结构 |
| 4 | 0x72E | 24 | `FA FA…` |
| 5 | 0x746 | 619 | **字符串池**（`default\0roothide\0$hidestring\0…`） |
| 6 | 0x9B1 | 445 | 规则/字节码样式数据 |
| 7 | 0xB6E | 0 | 空 |
| 8 | 0xB6E | 2048 | 页数据 |
| 9 | 0x136E | 2048 | 页数据 |
| 10 | 0x1B6E | 840 | 规则表 |
| 11 | 0x1EB6 | 12 | 3 个 u32 |

- 尾部 1712 B = **214 条重定位**（8 B/条），分布：
  `sec0×1、sec1×45、sec3×63、sec6×21、sec10×84`，其中 **99 条为 null 哨兵**。

### 51.3 重定位语义（YARA arena）

每条 `{section_idx, offset}` 指向某个 section 内偏移处的 8 字节槽，槽内是
`{u32 target_section, u32 target_offset}`：

- `(0xFFFFFFFF,0xFFFFFFFF)` → 写 0（空指针）；
- 否则 → 写 `arena_page[target_section] + target_offset`（指针）。

代码侧证据：

- 解析器 0x7DAFC–0x7DBA4 的循环正是该逻辑；
- 循环内调用的 `0x2B780`（目标 0x7D5B4）里打印的字符串是
  **`"yr_arena_ref_to_ptr 11"` / `"yr_arena_ref_to_ptr 33"`** ——
  即 YARA 的 `yr_arena_ref_to_ptr()`，尾部就是编译规则的 arena 引用重定位表。

### 51.4 模拟结果

```
parser ret = 0x0   fread_pos = 0x2572 (= file size)
table[0]=1 (refcount)  table[4]=12 (count)  table[0x188]=0x100000  table[0x190]=page list
sections (emulated arena, 1 MB pages):
  sec0  ptr=0x80000010  sec1 0x80100010  sec3 0x80200010  sec4 0x80300010
  sec5 0x80400010  sec6 0x80500010  sec8 0x80600010  sec9 0x80700010
  sec10 0x80800010  sec11 0x80900010   (sec2/sec7 为空，ptr=0)
after-reloc match 10/10（与 Python 模型逐字节一致）
```

### 51.5 工具

| 工具 | 作用 |
|---|---|
| `analysis/tools/parse_info_y.py` | 纯 Python 解析：头/MD5、12 段、214 条重定位、哨兵统计 |
| `analysis/tools/emu_info_y.py` | Unicorn 执行 0x7D924：伪造 I/O + 钩子 + .rela 重定位，输出 arena 表 |

### 51.6 结论

`info.y` 就是 **YARA 编译规则文件**：`INFO-` 容器 + 12 个 arena section +
尾部 `yr_arena_ref_to_ptr` 重定位表；壳加载后得到可用的 YARA ruleset，
再由 §47 的扫描线程对 `/proc/self/maps` 中的 `.so` 执行 `yr_scanner_scan_mem`。

---

## 52. `sub_9907C` 生成的 0x50 规则对象结构验证（2026-11-11）

### 52.1 结论

用 Unicorn 在解析出的 arena 上直接执行 `sub_9907C`，构建出的 **0x50 字节对象**
字段与 section 指针、内容全部吻合：**15/15 校验通过**。

对象是 **YARA 扫描器视角的 arena 视图**：首字段是 arena 本身，随后按固定顺序
引用 7 个 section，末尾 3 个 u32 是计数（来自 section 11）。

### 52.2 构建过程（0x9907C）

```
x20 = arena
malloc(0x50) -> obj
getter(arena, 0xB, 0) -> sec11            ; 三个计数
refcount++ (0x7D0E4 = ldr/add/str/ret)    ; arena 引用计数
obj[0x00] = arena
obj[0x40..0x44] = *(u64*)sec11            ; (9, 21)
obj[0x48]      = *(u32*)(sec11+8)         ; 1
obj[0x08] = getter(arena, 1, 0)           ; sec1
obj[0x10] = getter(arena, 3, 0)           ; sec3
obj[0x18] = getter(arena, 4, 0)           ; sec4
obj[0x20] = getter(arena, 8, 0)           ; sec8
obj[0x30] = getter(arena, 9, 0)           ; sec9
obj[0x28] = getter(arena, 10, 0)          ; sec10
obj[0x38] = getter(arena, 6, 0)           ; sec6
*out = obj
```

`getter` = `0x7D4B4(arena, idx, off)`：

```
x8 = arena + idx*0x18
x8 = [x8 + 8]        ; section 数据指针
return x8 + off
```

### 52.3 实测对象布局（本文件）

| 偏移 | 值 | 含义 |
|---|---|---|
| +0x00 | `0x80000000` | arena 指针 |
| +0x08 | `0x80100010` | sec1（480 B） |
| +0x10 | `0x80200010` | sec3（1176 B） |
| +0x18 | `0x80300010` | sec4（24 B，0 开头，作为链表头遍历时为空） |
| +0x20 | `0x80600010` | sec8（2048 B） |
| +0x28 | `0x80800010` | sec10（840 B） |
| +0x30 | `0x80700010` | sec9（2048 B） |
| +0x38 | `0x80500010` | sec6（445 B） |
| +0x40 | `9`（u32） | 计数 A |
| +0x44 | `21`（u32） | 计数 B |
| +0x48 | `1`（u32） | 计数 C |

同时 arena 引用计数 `1 → 2`（builder 会 retain）。

### 52.4 内容校验

对对象中 7 个 section 指针逐一读出数据，与「Python 解析 + 214 条重定位」得到的
section 内容比较：

```
sec1 (480B) OK   sec3 (1176B) OK  sec4 (24B) OK   sec8 (2048B) OK
sec10 (840B) OK  sec9 (2048B) OK  sec6 (445B) OK
字段校验 8/8 + 内容校验 7/7 = 15/15
```

### 52.5 下游用法（与 §47 的 worker 对应）

- `0x9B528`（worker ctx 构建）读取对象：
  - `+0x40 >> 6 + 1`、`+0x48 >> 6 + 1` 计算两缓冲区大小；
  - `+0x44 * 0x18` 计算另两块缓冲区大小（21 × 24 = 504 B）；
  - `+0x18`（sec4）当作链表头遍历（本文件首 u32=0，空表）；
  - `+0x30`（sec9）等作为扫描器页数据。
- 因此 0x50 对象就是 **YARA scanner/ruleset 的字段化视图**，把 arena 中的
  section 指针和计数一次性缓存下来供扫描线程使用。

### 52.6 工具

`analysis/tools/emu_rule_obj.py`：解析 info.y → 执行 `0x9907C` → 输出对象字段，
并与 getter 结果 / 重定位后的 section 内容逐项比对（当前 15/15）。

---

## 53. `info.y` 的 YARA 规则内容还原（2026-11-11）

### 53.1 结构映射（已验证）

| section | 内容 |
|---|---|
| sec0（16 B） | namespace 记录：`{name_ref → "default", 0}` |
| sec1（480 B） | **9 条规则**，每条 0x30 B；`+0x04`=字符串数，`+0x08`→规则名，`+0x20`→sec3 字符串块，`+0x28`→namespace |
| sec3（1176 B） | **21 条字符串描述符**，每条 0x38 B |
| sec5（619 B） | 字符串池（规则名、`$标识符`、字面量、hex 模式字节） |
| sec6/8/9/10 | 编译后的自动机/匹配表（条件为编译态，无源码文本） |

字符串描述符（0x38 B）：

```
+0x00 u32 flags      （0x0609/0x1609 = 文本；0x2064B/0x2164B = hex/二进制；bit 0x1000 为变体位）
+0x04 u32 全局串序号（0..20）
+0x08 u64 标记 0xFFFABADAFABADAFF
+0x10 u32 规则序号（0..8）
+0x14 u32 值长度
+0x18 ref → 值字节
+0x20 ref → NULL
+0x28 u64 0
+0x30 ref → "$标识符"
```

数量与 §52 的对象计数一致：`9 rules / 21 strings / 1 namespace`。

### 53.2 还原出的规则源码

（由 `analysis/tools/yara_dump.py` 生成；condition 为编译态，统一标注为 `any of them`）

```yara
rule roothide {
    strings:
        $hidestring = "_Z12hide_unmountv"
}

rule edxposed {
    strings:
        $word0000_text_string = "pm.dexopt.bg-dexopt"
        $word0001_text_string = "inline-max-code-units=0"
}

rule xposed {
    strings:
        $string1 = "addJarToClasspath"
}

rule fridasig {
    strings:
        $feature1 = "./lib/android"
        $feature2 = "art::JavaVMExt::AddGlobalRef"
        $feature3 = "art::ClassLinker::VisitClassLoaders"
}

rule yarfahook {
    strings:
        $symbol32_1 = { 00 00 00 00 00 00 9F E5 20 F0 90 E5 78 56 34 12 }
        $symbol32_2 = { 0C 00 9F E5 01 00 2D E9 00 00 9F E5 00 80 BD E8 78 56 34 12 78 56 34 12 }
        $symbol64_1 = { 00 00 00 00 60 00 00 58 10 00 40 F8 00 02 1F D6 78 56 34 12 89 67 45 23 }
        $symbol64_2 = { 60 00 00 58 90 00 00 58 00 02 1F D6 78 56 34 12 89 67 45 23 78 56 34 12 89 67 45 23 }
}

rule taichi {
    strings:
        $feature1 = { 74 61 69 63 68 69 }              // "taichi"
        $feature2 = { 6C 6A 61 67 44 }                  // "ljagD"
        $feature3 = { 47 65 64 6C 66 6C 59 }            // "GedlflY"
}

rule fupk3 {
    strings:
        $word0000_text_string = "Start to dump all dex files"
        $word0001_text_string = "Unable to found fupk interface"
}

rule youpk {
    strings:
        $word0000_text_string = "shouldUnpack"
        $word0001_text_string = "Unpacker"
}

rule fart {
    strings:
        $feature1 = { 64 75 6D 70 41 72 74 4D 65 74 68 6F 64 }        // "dumpArtMethod"
        $feature2 = { 64 75 6D 70 64 65 78 66 69 6C 65 62 79 41 72 74 4D 65 74 68 6F 64 }  // "dumpdexfilebyArtMethod"
        $feature3 = { 6D 79 66 61 72 74 49 6E 76 6F 6B 65 }          // "myfartInvoke"
}
```

### 53.3 观察

- 检测对象与 §41/§47 一致：Frida（`frida_agent_main` 相关）、Xposed/EdXposed
  （`addJarToClasspath`、`pm.dexopt.bg-dexopt`、`inline-max-code-units=0`）、
  YARFA hook、TaiChi、FUPK3、Youpk、FART，以及 RootHide（`_Z12hide_unmountv`）；
- `yarfahook` 的四条是 **ARM/ARM64 跳板指令模式**：
  - ARM32：`9F E5 / 20 F0 90 E5`（ldr/ldr pc）；
  - ARM64：`60 00 00 58 / 10 00 40 F8 / 00 02 1F D6`（ldr x0; ldur x16; br x16）；
- hex 值里的 `78 56 34 12` / `89 67 45 23`（0x12345678 / 0x23456789）是引擎标记
  （so@0xC8180/0xC8188 处存在这一对常量），出现在地址/目标不确定的位置，
  语义应为通配/未知字节占位；在还原源码中按原字节保留；
- `taichi` 的 `ljagD` / `GedlflY` 是变形串（非明文框架名），用于匹配混淆后的特征；
- **condition 不可还原为文本**：条件已编译为 sec6/sec10 的字节码/自动机，
  源码中的 `any of them` 只是占位；实际判定逻辑由 YARA VM 执行。

### 53.4 工具

`analysis/tools/yara_dump.py <info.y>`：输出上述 `.yar` 源码（含 flags/序号注释）。

---

## 54. condition 字节码还原（YARA VM 结构级）（2026-11-11）

### 54.1 结论

- condition 字节码位于 **section 6**（445 B），入口 `[rules+0x38]`；
- VM 在 `0x81DFC`（0x2A18），opcode 分派表在 **`0xC9CA4`**（u16 偏移，handler =
  `0x81F20 + off*4`），0x01–0x3F 为有效 opcode，0xFF 为结束；
- 值栈：`count @ sp+0x38`、`base @ sp+0x40`；未定义哨兵 `0xFFFABADAFABADAFF`；
- sec6 的 21 条重定位**不是跳转**，而是 **21 个字符串描述符指针**（每条紧跟在
  opcode `0x0D` 之后，全部指向 sec3 中对应的 0x38 B 描述符）；
- 程序按规则分块：每块以 `0x1C(块长度, 规则号)` 开头，块长度与实测边界完全一致
  （28/44/28/60/76/60/44/44/60）。

### 54.2 opcode 语义（已确认部分）

| opcode | 操作数 | 语义（证据） |
|---|---|---|
| `0x1C` | u32 块长度, u32 规则号 | 规则块头；handler 用规则号索引规则表（0x836C4） |
| `0x0D` | 8 B arena 引用 → 字符串描述符指针 | PUSH 字符串指针（重定位到 sec3） |
| `0x16` | — | **字符串是否命中**：取描述符 `+4` 的全局串号，查 `scanner+0x90`
  命中表，压入布尔（0x82818） |
| `0x2F` | u32 相对偏移 | 条件跳转；目标 = 当前指令地址 + 偏移；
  实测所有目标都落在指令边界（多为块尾的 `PUSH_INT 规则号`） |
| `0x01` | — | 逻辑 AND（两侧为布尔或未定义，0x82E34） |
| `0x02` | — | 逻辑 OR（0x82E94） |
| `0x03` | — | 逻辑 NOT（0x82A00） |
| `0x04` | — | 按位取反（`mvn`，0x82ED0） |
| `0x05–0x0A` | — | 二元算术族（ADD/SUB/MUL/DIV/MOD/SHL/SHR，共享尾块） |
| `0x1D` | u64 | PUSH 整数（压入规则号） |
| `0x31` | u32（本文件 0x20） | 待确认（出现于规则 4，疑为计数/阈值修饰） |
| `0xFF` | — | 结束 |

**待确认**：`0x2F` 的跳转极性（handler 为真值非 0 时走跳转路径，但栈上结果的
消费方式还需模拟确认）；`0x31` 的具体语义；`0x1D 规则号` 是“规则命中标记”还是
普通压栈。

### 54.3 逐规则解码（`analysis/tools/cond_dump.py`）

```
rule 0 roothide   : PUSH_STR s0 ; STR_MATCHED ; PUSH_INT 0
rule 1 edxposed   : PUSH_STR s1 ; STR_MATCHED ; JMP_IF +0x10(→0x3f)
                    PUSH_STR s2 ; STR_MATCHED ; AND ; PUSH_INT 1
rule 2 xposed     : PUSH_STR s3 ; STR_MATCHED ; PUSH_INT 2
rule 3 fridasig   : s4 ; JMP +0x10(→0x87) ; s5 ; AND ; JMP +0x10(→0x97) ; s6 ; AND ; PUSH 3
rule 4 yarfahook  : s7 ; JMP +0x10(→0xc3) ; s8 ; AND ; OP31 0x20 ;
                    s9 ; JMP +0x10(→0xe2) ; s10 ; AND ; OR ; PUSH 4
rule 5 taichi     : s11 ; JMP ; s12 ; AND ; JMP ; s13 ; AND ; PUSH 5
rule 6 fupk3      : s14 ; JMP ; s15 ; AND ; PUSH 6
rule 7 youpk      : s16 ; JMP ; s17 ; AND ; PUSH 7
rule 8 fart       : s18 ; JMP ; s19 ; AND ; JMP ; s20 ; AND ; PUSH 8
```

映射的 21 个字符串见 §53（s0 = `$hidestring` … s20 = `$feature3` of fart）。

### 54.4 条件形态（推断）

- 单串规则（roothide、xposed）：结果 = 该串命中；
- 多串规则：`STR_MATCHED` + 条件跳转 + `AND` 的组合，形式为
  “**若干字符串命中组合**”；规则 4 唯一出现 `0x02`（OR）与 `0x31 0x20`，
  说明 yarfahook 的条件是 **两组匹配的 AND/OR 组合**（疑为
  `(s7∧s8) ∨ (s9∧s10)` 或带计数阈值的变体）；
- 由于 `0x2F` 极性与 `0x31` 尚未最终确认，条件文本仍标注为推断；
  但可以确定条件**只由这 21 个字符串的命中布尔值参与**，没有复杂的偏移/长度约束。

### 54.5 工具

`analysis/tools/cond_dump.py <info.y>`：按规则块输出上表；跳转目标已校验落在
指令边界。

---

## 55. 模拟执行 condition 字节码：条件真值表与最终语义（2026-11-11）

### 55.1 VM 语义补全（已确认）

在 §54 基础上，根据 handler 与跳转尾块逐条确认：

| opcode | 语义 |
|---|---|
| `0x2F rel` | **JFALSE**：`top==0`（或未定义）→ `pc += rel`，否则 `pc += 5` |
| `0x31 rel` | **JTRUE**：`top!=0` → `pc += rel`，否则 `pc += 5` |
| `0x1D rule` | **上报结果**：弹出布尔，调 `0x2C450` 更新 `rule[rule]` 的命中状态 |
| `0x0D` / `0x16` | push 字符串描述符指针 / 压入“该串是否命中” |

`0x31` 为 JTRUE 的依据：规则 4 中 `0x31` 位于 `0xC3`、操作数 `0x20`，
目标 `0xC3+0x20=0xE3` 正好是该规则的上报指令；真值表也与 OR 短路的预期完全一致。

### 55.2 模拟执行（`analysis/tools/cond_vm.py`）

VM 读取 sec6、按块执行、遍历每条规则所有字符串命中组合，得到真值表：

```
rule 0 roothide    strings=[0]             true: 1
rule 1 edxposed    strings=[1,2]           true: 11
rule 2 xposed      strings=[3]             true: 1
rule 3 fridasig    strings=[4,5,6]         true: 111
rule 4 yarfahook   strings=[7,8,9,10]      true: 0011 0111 1011 1100 1101 1110 1111
rule 5 taichi      strings=[11,12,13]      true: 111
rule 6 fupk3       strings=[14,15]         true: 11
rule 7 youpk       strings=[16,17]         true: 11
rule 8 fart        strings=[18,19,20]      true: 111
```

### 55.3 最终 condition（还原结果）

```yara
rule roothide   { condition: $hidestring }
rule edxposed   { condition: $word0000_text_string and $word0001_text_string }
rule xposed     { condition: $string1 }
rule fridasig   { condition: $feature1 and $feature2 and $feature3 }
rule yarfahook  { condition: ($symbol32_1 and $symbol32_2)
                          or ($symbol64_1 and $symbol64_2) }
rule taichi     { condition: $feature1 and $feature2 and $feature3 }
rule fupk3      { condition: $word0000_text_string and $word0001_text_string }
rule youpk      { condition: $word0000_text_string and $word0001_text_string }
rule fart       { condition: $feature1 and $feature2 and $feature3 }
```

即：
- 8 条规则为“全部字符串命中”（AND 链）；
- `yarfahook` 为两组 AND 的 OR：`($symbol32_1 ∧ $symbol32_2) ∨ ($symbol64_1 ∧ $symbol64_2)`。

### 55.4 完整规则（字符串 + 条件）

| 规则 | 字符串 | 条件 |
|---|---|---|
| roothide | `$hidestring="_Z12hide_unmountv"` | 该串 |
| edxposed | `pm.dexopt.bg-dexopt`、`inline-max-code-units=0` | 两串均中 |
| xposed | `$string1="addJarToClasspath"` | 该串 |
| fridasig | `./lib/android`、`art::JavaVMExt::AddGlobalRef`、`art::ClassLinker::VisitClassLoaders` | 三串均中 |
| yarfahook | ARM32/ARM64 跳板 hex ×4 | (前两串) 或 (后两串) |
| taichi | `taichi`、`ljagD`、`GedlflY` | 三串均中 |
| fupk3 | `Start to dump all dex files`、`Unable to found fupk interface` | 两串均中 |
| youpk | `shouldUnpack`、`Unpacker` | 两串均中 |
| fart | `dumpArtMethod`、`dumpdexfilebyArtMethod`、`myfartInvoke` | 三串均中 |

### 55.5 工具

- `analysis/tools/cond_vm.py`：Python VM 执行 sec6，输出每规则真值表；
- `analysis/tools/cond_dump.py`：线性反汇编（§54）；
- `analysis/tools/yara_dump.py`：生成 .yar 源码（可结合本节条件替换占位的 `any of them`）。

---

## 56. 用还原规则扫设备 so（2026-11-11）

### 56.1 方法

- 拉取设备 `lib/arm64`：**56 个 .so，共 99 MB**（与壳 §48 的扫描对象一致：文件内容）；
- 按 §53/§55 还原的 9 条规则逐文件精确匹配；hex 字符串（yarfahook）按引擎标记
  `0x12345678/0x23456789` 分段匹配，并对“标记/前导零视为通配”的放宽版本复扫；
- 条件按 §55：8 条为字符串全中（AND），yarfahook 为
  `($symbol32_1∧$symbol32_2) ∨ ($symbol64_1∧$symbol64_2)`；
- 额外在设备侧扫描 `/system/lib64`、`/apex/*/lib64`、`/system_ext/lib64`、`/vendor/lib64`
  （壳的 maps 扫描同样覆盖系统库）。

### 56.2 结果

```
scanned 56 libraries
rule roothide   no hit
rule edxposed   no hit
rule xposed     no hit
rule fridasig   no hit
rule yarfahook  no hit
rule taichi     no hit
rule fupk3      no hit
rule youpk      no hit
rule fart       no hit
```

- 系统库目录同样 **0 命中**；
- 唯一“部分命中”：`libNetHTProtect.so`、`libapminsightb.so` 含 `"Unpacker"`
  （8 B 子串），但上下文是 **XZ 解压器符号** `XzUnpacker_Construct/Code/...`，
  且 youpk 规则的另一字符串 `"shouldUnpack"` 不存在 → 规则不成立；
- yarfahook 的 4 条 ARM/ARM64 跳板模式（含去掉前导零的放宽版本）均无命中。

### 56.3 结论

- 该设备当前**没有安装任何命中规则库的 Hook/脱壳框架**（Frida/Xposed/EdXposed/
  TaiChi/Youpk/FUPK3/FART/YARFA/RootHide）；
- 结果与壳自身扫描逻辑一致：壳只读 `/proc/self/maps` 中映射的 `.so` **文件内容**，
  本例中同样会判为干净；
- 侧面验证了 §53–§55 的规则还原与 §48 的“读文件而非扫描内存”结论。

### 56.4 工具

`analysis/tools/scan_rules.py <info.y> <dir>`（`--verbose` 输出部分命中）：
解析 info.y → 逐 .so 匹配 → 按还原条件判定 → 输出每规则命中。

---

## 57. 构造测试 so 验证规则命中（2026-11-11）

### 57.1 方法

用 `clang -target aarch64-linux-gnu -c` 生成 **13 个真实 AArch64 ELF 对象**（.so 命名）：

| 文件 | 内容 | 预期 |
|---|---|---|
| libtest1 | `_Z12hide_unmountv` | roothide 命中 |
| libtest2 | `pm.dexopt.bg-dexopt` + `inline-max-code-units=0` | edxposed 命中 |
| libtest3 | `addJarToClasspath` | xposed 命中 |
| libtest4 | fridasig 三条字符串 | fridasig 命中 |
| libtest5 | `$symbol32_1`+`$symbol32_2` 的具体字节（通配处填 0x11223344 等） | yarfahook 命中 |
| libtest6 | `$symbol64_1`+`$symbol64_2` 的具体字节 | yarfahook 命中 |
| libtest7 | 仅 `$symbol32_1` + `$symbol64_1`（混合） | **不命中**（验证 OR-of-ANDs） |
| libtest8 | `taichi`/`ljagD`/`GedlflY` | taichi 命中 |
| libtest9 | fupk3 两条字符串 | fupk3 命中 |
| libtest10 | `shouldUnpack`+`Unpacker` | youpk 命中 |
| libtest11 | fart 三条字符串 | fart 命中 |
| libtest12 | 仅 `Unpacker` | **不命中**（反例） |
| libtest13 | 仅 `pm.dexopt.bg-dexopt` | **不命中**（反例） |

hex 模式在标记位（`12345678/23456789`）填入任意字节，验证“标记=通配”的分段匹配。

### 57.2 结果（`scan_rules.py /tmp/info.y /tmp/testlibs --verbose`）

```
rule roothide   HIT: libtest1.so
rule edxposed   HIT: libtest2.so        (partial libtest13: 只有一条 → 不命中)
rule xposed     HIT: libtest3.so
rule fridasig   HIT: libtest4.so
rule yarfahook  HIT: libtest5.so, libtest6.so
                (partial libtest7: 32_1+64_1 混合 → 不命中)
rule taichi     HIT: libtest8.so
rule fupk3      HIT: libtest9.so
rule youpk      HIT: libtest10.so       (partial libtest12: 只有 Unpacker → 不命中)
rule fart       HIT: libtest11.so
```

**13/13 与预期一致**：
- 9 条规则各自的正例全部命中；
- 3 个反例（混合 hex、单独 `Unpacker`、单独 `pm.dexopt.bg-dexopt`）全部不命中，
  验证了“AND 链”条件；
- yarfahook 的 `(s32_1∧s32_2) ∨ (s64_1∧s64_2)` 逻辑被 test5/test6/test7 三例精确验证。

### 57.3 结论

- §53（字符串）、§54–§55（条件）的还原结果是**可执行且可判别**的；
- hex 字符串中的 `0x12345678/0x23456789` 按“通配占位”处理后匹配成功，与 §53.3 的推断一致；
- 设备实扫（§56）为 0 命中，结合本次正例验证，可确认设备确实不含这些框架。

---

## 58. 用壳的 YARA 引擎扫测试 so（Unicorn 模拟，2026-11-11）

### 58.1 已打通的链路

```
parse info.y (0x7D924)
  -> build 0x50 rules object (0x9907C)
  -> build scanner ctx (0x9B528)
  -> set callback 0x4F414 (0x9B71C) / flags=0x18 (0x9B738) / timeout (0x9B724)
  -> write YARA config table 0xF4020 = {0x4000, 0x2710, 0x200}
  -> _yr_scanner_scan_mem(ctx, data, len)  (0x9BF94 -> 0x9B8C8)
```

补齐的 libc 钩子：fread/malloc/realloc/free/memset/memcmp/read thunk、puts、close、
gettimeofday、memcpy/strlen/strnlen/strcpy、printf、pthread_key_create/delete/
setspecific、pthread_mutex_*、sigaction/sigfillset/sigsetjmp。

**引擎返回 `ERROR_SUCCESS (0)`**，并按规则回调（mode 1=命中，2=未命中，3=结束）。

### 58.2 结果（13 个测试 so）

| 文件 | 期望命中 | 引擎报告 |
|---|---|---|
| libtest1 roothide | rule0 | rule0 ✓（另有 rule2 误报） |
| libtest2 edxposed | rule1 | rule1 ✓（另有 rule2） |
| libtest3 xposed | rule2 | rule2 ✓ |
| libtest4 fridasig | rule3 | **扫描崩溃**（0x9B3F8 写未映射） |
| libtest5/6 yarfahook（通配填充） | rule4 | **未命中** |
| libtest7 混合 hex | 无 | 无 ✓ |
| libtest8 taichi | rule5 | rule5 ✓（另有 rule2） |
| libtest9 fupk3 | rule6 | rule6 ✓（另有 rule2） |
| libtest10 youpk | rule7 | rule7 ✓（另有 rule2） |
| libtest11 fart | rule8 | rule8 ✓（另有 rule2） |
| libtest12/13 反例 | 无 | **rule2 误报** |
| 空数据对照 | 无 | 全部未命中 ✓ |

### 58.3 发现的差异与原因

1. **rule2（xposed, `$string1`）在含数据的文件上恒定误报**：VM 的字符串检查（0x82840）
   显示 idx 3/4 被判为命中，match 表条目 +8 字段是 **数据偏移**（如 `0x44` 恰为
   "Unpacker" 的位置），说明本模拟中 AC 自动机输出的 **串号映射** 与描述符 idx 不完全一致，
   或运行时表（lowercase/altercase）未完整初始化。
2. **hex 字符串用例**：引擎在 AC 阶段崩溃（0x9B0F8 读未映射），无法判定
   `0x12345678/0x23456789` 是字面量还是通配；Python 模型（§57）按通配处理，
   但引擎实证暂缺。
3. **长字符串用例（fridasig）**：在 match-list 链接处写未映射（0x9B3F8），同属 AC
   内部状态在合成环境中的不完整。
4. 调用真实 YARA 初始化 `0xA0E7C` 失败（内部仍有未 hook 的导入），当前使用手工写入的
   配置表。

### 58.4 结论与后续

- 壳的 YARA **引擎主体可在 Unicorn 中跑通**：解析 → 对象 → scanner → scan 成功，
  文本字符串规则（roothide/edxposed/xposed/taichi/fupk3/youpk/fart）的命中判定与
  还原规则一致；
- 全保真还差两块：YARA 运行时初始化（大小写表/模块）与 AC 自动机在合成内存中的
  完整状态。补齐后即可对 hex 模式与长字符串做引擎级判定；
- 工具：`analysis/tools/emu_yara_scan.py`（含全部钩子与诊断输出）。

### 58.5 ABS64 修复后的复测（2026-11-11 补）

发现并修复了一个关键重定位缺口：YARA 模块表/函数指针使用 **R_AARCH64_ABS64 (257)**，
而此前模拟只应用了 1024–1027。补上 257 后：

- `YARA init (0xA0E7C)` **成功**（完成 lowercase/altercase 表、模块初始化、
  配置表 0xF4020={0x4000,0x2710,0x200}）；
- 扫描仍返回 `ERROR_SUCCESS (0)`；
- 但复测 14 个用例仍存在模拟层 artifact：

| 现象 | 用例 |
|---|---|
| rule2（xposed）恒定误报 | 除空数据外全部 |
| rule4（yarfahook）部分误报 | libtest2/9/11 |
| 扫描崩溃（AC 阶段读写未映射） | libtest3/4/14 |
| hex 用例未命中 | libtest5/6（通配填充） |

定位：VM 字符串检查读到的 match 表条目 `+8` 在部分串上出现 `0x44/0x49` 这类
**数据偏移值而非指针**（如 libtest12 中 `0x44` 恰为 "Unpacker" 位置），说明
合成环境里 YARA 的 **match arena/链表（指针 vs arena ref）与真实分配布局不一致**；
部分用例在 AC 自动机遍历时越界。属模拟保真度问题，不是规则还原错误。

**结论**：壳的 YARA 引擎流程（parser → rules 对象 → scanner ctx → init → scan →
规则回调）已在 Unicorn 中打通并能返回成功；文本规则的命中集合与 §55 模型一致
（rule0/1/5/6/7/8 正确）。但要做到 hex/长串的**引擎级全保真判定**，还需复刻
YARA 的 match arena 分配，或在真实进程内运行引擎——当前最可靠的规则验证仍是
§55 Python VM + §57 测试 so + §56 设备实扫。

---

## 59. match arena 布局攻破：引擎级全保真（2026-11-11）

### 59.1 根因：`0x2B390` 是 `calloc`，不是 `malloc`

用内存写钩子跟踪 `ctx+0x90/0x98` 发现两张 match 表只相隔 0x20 字节（应为 0x1F8），
进一步确认：

- `0x2B390 -> 0x8F3FC -> b 0x2B2A0`，`0x2B2A0 = calloc`；
- parser 的 arena 表：`calloc(1, 0x1A0)`；
- scanner 的 match 表：`calloc(21, 0x18)` ×2（= 0x1F8 每张）；
- 此前的模拟按 `malloc(x0)` 处理，只分配了 1/21 字节 → 两表重叠、写越界，
  造成 rule2 恒误报、部分用例 AC 崩溃。

修复 `calloc(count,size)`（分配 count*size 并清零）后，再加此前两项修复：

1. **R_AARCH64_ABS64(257)** 重定位（模块表/函数指针）；
2. 调用真实 **YARA init `0xA0E7C`**（lowercase/altercase 表、模块、配置表）。

### 59.2 最终引擎矩阵（`emu_yara_scan.py`）

14 个测试 so，全部 `scan ret = 0`，无一崩溃、无一假阳：

| 测试 | 期望 | 引擎 |
|---|---|---|
| libtest1..4 | rule0..rule3 | 一致 |
| libtest5/6（标记位被替换） | 不命中 | 不命中 |
| libtest7（混合 hex） | 不命中 | 不命中 |
| libtest8..11 | rule5..rule8 | 一致 |
| libtest12/13（反例） | 不命中 | 不命中 |
| libtest14（含原始标记字节） | rule4 | 命中 |

**14/14 与规则模型一致**，且每个正例只命中预期的那一条规则。

### 59.3 关键修正：`12345678/23456789` 是字面量

- libtest14 把 `78 56 34 12`、`89 67 45 23` **按原字节**写入 → yarfahook 命中；
- libtest5/6 把这两个位置替换成任意字节 → **不命中**。

结论：hex 字符串里的 `0x12345678/0x23456789` 是**模式的一部分，不是通配占位**。
§53.3/§56/§57 中“按通配分段处理”的推断作废；`scan_rules.py` 已改为纯精确匹配，
设备实扫结论不变（仍 0 命中）。

### 59.4 引擎保真清单（复现要点）

1. 应用全部重定位：1024/1025/1026/1027 + **257 (ABS64)**；
2. `calloc` 语义（0x2B390）；
3. YARA init `0xA0E7C`（模块表初始化，srand/tolower 等钩子）；
4. scanner ctx 字段：`+0x20/+0x28` 回调（0x9B71C）、`+0x10` flags（0x9B738）、
   `+0x18` 超时（0x9B724）；
5. 回调 `0x4F414`（mode 1=命中/2=未命中/3=结束），rule 指针按 `obj+8` 换算索引。

工具：`analysis/tools/emu_yara_scan.py`（`TRACE_MATCH=1` 可看 match 表写入）。

---

## 60. YARA 命中回调 `0x4F414` 的处置链（2026-11-11）

### 60.1 总览

```
scan 命中 → callback 0x4F414(mode=1, rule_rec)
   ├─ 取 rule_rec+8 = 规则名（如 "roothide"/"edxposed"/"yarfahook"…）
   ├─ 子串匹配分类：frida / xposed / root / 其他
   └─ 0x2DBC0(kind, tag, 0xFFF)
        ├─ 开关：config = *(0xE9DD0→0xEF010)；[config+0x14C] & kind
        │    └─ 未启用 → 直接返回
        ├─ 构造上报串（root/app/prop/xposed/frida/debug…，按 kind 混淆分发）
        ├─ 长度 < 0x80 → memcpy 到 128B 栈缓冲
        │     → 0x2D8F4(buf)；返回 0 时 → 0x2D5E4(buf, 1)
        │     （文件型上报：fopen/flock/fseek/ftell/fgets，非网络）
        ├─ 长度 ≥ 0x80 → abort()
        └─ _exit(3) 仅存在于 0x2DE00 的混淆分支（反篡改/诱饵路径）
```

### 60.2 回调本体（0x4F414）**[静态]**

- 仅处理 **mode 1（规则命中）**；mode 2/3 直接 `return 0`；
- 从 `rule_rec+8` 取规则标识符，逐字节搜索三个关键字：

| 命中关键字 | kind | 附带常量 tag |
|---|---|---|
| `frida` | `0x100` | `0xb6a2897c` |
| `xposed` | `0x80` | `0xb6a2888c` |
| `root` | `0x1` | `0xb6a281fa` |
| 其他 | `0x200` | `0xb6a28a6f` |

- 最后 `0x2DBC0(kind, tag, 0xFFF)`。

### 60.3 处置函数 `0x2DBC0`（0x42C B）**[静态]**

- **开关位**：`config = *(0xE9DD0)`（GOT → `0xEF010`，运行时对象）；
  `mask = [config+0x14C]`；`tst mask, kind` 为 0 → 直接返回（该类检测被关闭）。
- 启用后按 kind 走混淆跳转表（表 @`0xC2A70`，字节偏移 ×4 + `0x2DE68`），
  从预构造字符串（`root`/`app`/`prop`/`xposed`/`frida`/`debug` 等）中选一条消息；
- 消息长度 ≥ 0x80 → `abort()`；为空 → 跳过；
- 正常路径：`memcpy` 到 128 B 缓冲 → `0x2D8F4(buf)` → 若返回 0 → `0x2D5E4(buf, 1)`；
- `_exit(3)` 位于 `0x2DE00 → 0x2DE30` 的混淆分支（`getpid` + `0x384F0` + `_exit(3)`），
  不是常规命中路径。

### 60.4 上报后端（0x2D8F4 / 0x2D5E4）**[静态]**

两个函数导入的 libc 只有文件/字符串族：

```
malloc, access, fopen, fclose, fileno, flock, fseek, ftell, fgets, isspace,
snprintf, __strlen_chk
```

- 路径 `snprintf("%s%s", dir, name_buf)`：`dir = *(0xE9F80)`（GOT → `0xEF018`，运行时目录），
  `name_buf` 由常量片段拼成（本构建为 `envc.push` 样式）；
- 行格式 `snprintf("%10s=", msg)` 之类，配合 `flock` 加锁、`fseek/ftell` 定位，
  属**本地文件队列/日志**，无 socket/网络调用；
- 设备上未出现该文件，与“从未命中任何规则”（§56）一致。

### 60.5 结论

- 命中后的处置是 **分类 + 开关过滤 + 写入本地上报文件**，不是立即杀进程；
- 真正可能终止进程的 `abort/_exit` 位于混淆/反篡改分支，常规检测命中不会触发；
- 结合 §59 的引擎与 §56 的实扫，可完整描述壳的检测闭环：
  `解析 info.y → YARA 扫描 .so 文件 → 命中分类 → 配置过滤 → 本地上报`。

工具：`analysis/tools/emu_yara_scan.py`（可观察 callback 参数）。

---

## 61. 自毁原语 `0x384F0`：裸 `kill(pid, SIGKILL)`（2026-11-11）

### 61.1 函数本体 **[静态]**

`0x384F0`（`0x3C` B）不是普通 libc 包装，而是**直接 `svc` 的 `kill` 系统调用**：

```
0x384F0  str  x19, [sp, #-0x20]!
0x384F4  stp  x29, x30, [sp, #0x10]
0x384FC  mov  w1, #9              ; SIGKILL
0x38500  sxtw x0, w0              ; pid（由调用者传入）
0x38504  mov  x8, #0x81           ; __NR_kill = 129 (arm64)
0x38508  svc  #0
0x3850C  cmn  x0, #0xfff          ; 出错？
0x38514  neg  w19, w0
0x38518  bl   0x2B720             ; __errno
0x3851C  str  w19, [x0]
0x38528  ret
```

- 语义：`kill(pid, SIGKILL)`；失败时 `errno = -ret`，无返回值。
- **完全绕过 libc/PLT**：so 的导入表里没有 `kill`，桩函数（`0x2B700` 等）也不参与；
  Frida/Native hook 常见的 `kill`、`getpid`、`exit` 拦截对它无效。
- `SIGKILL` 不可捕获、不可阻塞，进程内信号处理器与 `ptrace` 注入都无法改变结局。

### 61.2 七个 `bl 0x384F0` 调用点 **[静态]**

| 调用点 | 所在函数 | 触发上下文 |
|---|---|---|
| `0x2DE34` | `sub_2DBC0`（YARA 命中处置，§60.3） | 消息为空/混淆分支（`0x2DE00` 的非零判断失败） |
| `0x2F21C` | `handle_exception_sig`（`0x2F1A4`，`(int sig, int code, …)`） | **信号 ≠ SIGTRAP(5)** 时：记录后自毁；SIGTRAP 走特殊反调试路径 |
| `0x328E0` | `0x2F7F0` 起的大函数（符号表标为 `JNI_OnLoad`，含 DEX 主线 `0x3185C`） | 函数尾部的**混淆完整性检查**（`0x328B0`）失败 |
| `0x518BC` | `sub_51024`（JNI 桥 + 反调试观察者） | 栈保护/校验失败（`0x518B4` 的 `__stack_chk_fail` 分支）后：`getpid → kill → exit(0)` |
| `0x559B4` | `sub_552A4`（`/proc` 进程扫描器） | 结果码 `w19==2`（子进程/环境异常）：logcat → `getpid → kill → _exit(3)` |
| `0x55A78` | `sub_559C4`（fd/管道辅助子进程） | `read` 或 `errno` 路径异常 |
| `0x55BF8` | `sub_55A84`（`waitpid` 子进程监控） | 子进程异常退出/被信号杀死 |

统一模板：

```
bl getpid          ; 0x2B840（同样是 PLT 桩，可被 hook——所以内联变体也大量存在）
bl 0x384F0         ; kill(self, SIGKILL)
mov w0, #3
bl _exit           ; 0x2B700；kill 失败（如 seccomp 拦截）时的兜底
```

`0x518BC` 略有不同：`… ; mov w0, wzr ; bl exit`（`0x2CB60`，即 `exit(0)`）。

`0x2DE00` / `0x2F1E8` / `0x328B0` 三处是**同一编译期混淆构件**的实例：
`mov x0,x30; add x0,#0x8e5; … ; cbz/tbnz 条件` → 条件不满足即 `getpid + kill + _exit(3)`。
它们出现在多个函数尾部，属于壳注入的“完整性/一致性检查失败即自杀”代码，而不是业务逻辑。

### 61.3 内联的裸系统调用变体 **[静态]**

同一批反调试函数里还直接内联了 `svc`，连包装函数都不走：

| 系统调用 | `x8` | 内联位置 |
|---|---|---|
| `kill` | `0x81` | `0x5137C`、`0x51588`、**`0x518A4`（`kill(-1, SIGKILL)`，杀光可信号进程）**、`0x54D98`、`0x558F4` |
| `getpid` | `0xAC` | `0x50924`、`0x50C60`、`0x50FDC`、`0x5155C`、`0x51878` |
| `read` | `0x3F` | `0x385E0`、`0x4ECB0`、`0x50458`、`0x53C14`、`0x55A1C`、`0x58BA0`、`0x5D478`、`0x85344` |

目的很明确：**libc 层 hook 无效**。`getpid` 直取真实 pid（防伪造/防 hook 返回假值），
`read` 用于父子进程管道的原语同步（见 §61.4），`kill` 用于清场。

### 61.4 调用者的检测面（静态导入 + 字符串） **[静态]**

- `sub_552A4`：导入 `fork`、`pipe`、`execl`、`select`、`__FD_SET_chk`、`fdopen`、`fscanf`、
  `strcasestr`、`access`、`open`、`read`、`sleep`、`atoi`；
  字符串 `/proc/%ld/cmdline`、`/proc/%ld/net`、`/proc/%ld/task`、`/proc/%ld/status`、
  `%*s %d`、`linker64` → **fork 子进程扫描进程表 / `/proc/net` / 线程名**，定位
  `frida-server`、调试器、注入线程。结果码：`1` = 命中 → `0x2DBC0(0x20, 0xb6a286af, 0xFFF)`；
  `2` = 环境异常 → logcat + 自毁。
- `sub_559C4`：`free` + `prctl(PR_SET_DUMPABLE, 1)` + 裸 `read(1B)` → 辅助/被监控子进程的握手端。
- `sub_55A84`：`waitpid` ×2 + 手工解析 wait status（`WIFSIGNALED`/`WTERMSIG` 位运算）→
  子进程被信号杀死或异常退出即自毁；这是“检测子进程被 tracer 干掉 → 父进程同归于尽”的闭环。
- `sub_51024`：JNI（`NewObject`/`CallObjectMethod`/`CallStaticObjectMethod`/`CallBooleanMethod`）
  + `fork`/`pipe`/`select`/`execl`/`setenv`，并调用 `0x2DBC0` 上报；末尾校验失败走 `kill + exit(0)`。
- 配置门控：`0x558E0` / `0x54D70` 处 `[config+0x14C]` 的 **bit 5（`0x20`）** 为 1 时跳过自毁，
  为 0 时直接 `kill(pid, SIGKILL)`；随后才按结果码上报。即“静默杀死”与“上报”受同一配置对象控制。

### 61.5 预杀日志 **[静态]**

`sub_552A4` 在结果码 2 分支先打 logcat 再自杀：

```
__android_log_print(5, "LOG.OUT", "%d, %x, %x", pid, 0xb6a286af, 0xfff)   ; 0x559AC
__android_log_print(5, "LOG.OUT", "%d, %x, %x", pid, 0xb6a2861f, 0xfff)   ; 0x55A70
```

- 级别 5 = `ANDROID_LOG_WARN`；tag 固定 `"LOG.OUT"`；
- `0xb6a286af` / `0xb6a2861f` 是 liblog 的**压缩 tag 常量**（与 §60.2 回调里
  `0xb6a2897c`/`0xb6a2888c`/`0xb6a281fa`/`0xb6a28a6f` 同一族），`0xfff` 为固定哨兵值；
- 设备上可通过 `logcat -s LOG.OUT` 观察自毁前的触发点（若日志级别未被裁剪）。

### 61.6 结论

- `0x384F0` 是壳反篡改体系的**最终执法原语**：检测命中、信号异常、完整性校验失败、
  子进程异常 → `kill(self, SIGKILL)`；`_exit(3)` 只是 kill 被拦时的兜底退出。
- 因为是裸 `svc`，Frida 对 `kill`/`getpid`/`exit` 的 Interceptor hook 不生效；
  想在动态分析中拦截/观测，只能走 **syscall 层**（seccomp、ptrace `PTRACE_SYSCALL`、
  Stalker 指令级）或直接 patch `0x384F0` 与各处内联 `svc`。
- 与 §60 合并后，壳的完整处置链为：
  `YARA/反调试检测 → 0x2DBC0 分类 + 配置门控 → 本地上报`；
  **自毁只在完整性/异常/子进程异常/配置指定分支触发**，常规规则命中不自杀。
- 已知“注入后 2–15 s 进程消失”的现象与这条 `SIGKILL` 路径一致；若观察到
  `exit_group(0)` 而非信号 9 退出，则来自另一条路径（本 so 内未发现裸 `exit_group` 调用）。

---

## 62. x86_64 变体 `libDexHelper-x86.so` 解包（2026-11-12）

### 62.1 样本与 ELF 结构 **[静态]**

- 文件：`analysis/libDexHelper/libDexHelper-x86.so`，1,146,813 B，
  SHA-256 `1b7de9a780854c769f45989eea88baf51320b144f7db3ae2ac5ff3e5d404e2fc`；
- 它就在本 APK 的 `lib/arm64-v8a/` 目录下（与 arm64 主壳同包），说明是同一构建的
  另一架构产物，而非 x86 设备专用包；
- ELF64 / EM_X86_64，5 个 phdr：

| # | 类型 | p_offset | p_vaddr | p_filesz | p_memsz | 权限 |
|---|---|---|---|---|---|---|
| 0 | PT_LOAD | 0 | 0 | 0x10C980 | 0x10C980 | R+X |
| 1 | PT_LOAD | 0x10CFF0 | 0x10DFF0 | 0x9320 | 0x2209C | R+W |
| 2 | PT_DYNAMIC | 0x1178F0 | 0x111498 | 0x260 | 0x260 | R+W |
| 3 | PT_GNU_EH_FRAME | 0x10987C | 0x10987C | 0x3104 | — | R |
| 4 | PT_LOAD | 0x117078 | 0x131078 | 0x863 | 0x863 | R+X |

- **双 `PT_DYNAMIC` 是同一套诱饵**：`p_offset=0x1178F0` 指向假表（只有
  `DT_NEEDED`/`DT_SONAME`）；linker 按 `p_vaddr=0x111498` 读内存，对应文件
  **`0x110498`** 的真表：

```
DT_SYMTAB 0x2C0   DT_SYMENT 0x18   DT_STRTAB 0x9140  DT_STRSZ 0xED98
DT_HASH   0x1A7C0 (nbucket 1031 / nchain 1520)      DT_GNU_HASH 0x17ED8
DT_RELA   0x1DBE0 (0x9EB8)         DT_JMPREL 0x27A98 (0x3E70, RELA)
DT_INIT   0x131098
```

- 段 1 的 `p_offset`/`p_vaddr` 差 `0x1000`。bionic 按页 `mmap` 整页，因此
  **`p_filesz` 之外、但落在最后页内的文件字节仍然可见**：`TBOX0/1/2`、`PADDING`、
  `vtag`、`dexflag` 等位于 va `0x113000+` 的数据实际在文件 `va-0x1000` 处。
  这条“页粒度可见”是读懂该样本的关键（按 `p_offset+p_filesz` 截断会以为它们是 bss）。

### 62.2 `DT_INIT` 引导链（`0x131098`） **[静态+Unicorn]**

```
call $+5; pop rdx                  ; 取 PC
rsi = rdx - 0x2D                   ; 引导头 = 0x131078
delta = rsi - [rsi+0x10]           ; 运行时基址 - 链接基址（0x131078）
payload = delta + [header+0x18]    ; = delta + 0x2B908
mmap(NULL, [header+0x28], RWX, PRIVATE|ANON) ; 0x61A85 字节（压缩体）→ 复制
mprotect(delta, 0x10D000, 7)       ; 整个首段 RWX
decompress(dest=delta+0x2B908, src=mmap_buf, in=0x61A85)
reloc_apply(delta+0x117310, count=[header+0x14]=0)   ; 本构建空操作
munmap(mmap_buf)
混淆栈恢复 + jmp [rsp-0x48]        ; 反模拟返回
```

引导头（va `0x1318AF`，44 B）：

| 偏移 | 值 | 含义 |
|---|---|---|
| +0x00 | 0 | 重定位条目数（0） |
| +0x08 | 0x622E9 | 入口/校验提示值 |
| +0x0C | 0x2B908 | 压缩体 VA |
| +0x10 | 0x117310 | 重定位表 VA |
| +0x1C | 0xE1078 | **解压后大小** |
| +0x24 | 0x2B908 | 解压目的 VA |
| +0x28 | 0x61A85 | **压缩体大小** |

解压器 `0x13168F`（`0x131674` 是参数转接）：

- 输入按字节装载，每字节提供 **7 个 bit（bit7..bit1，MSB 优先）**，bit0 恒为 1 作哨兵；
- 标志位 1 → literal：直接读下一个原始字节输出；
- 标志位 0 → LZ match：继续读长度/距离位，`0x500` 为长距离阈值，`0xFFFFFFFF` 为流结束；
- 输出大小写回 `[rcx]`，返回 0 表示输入恰好读完。

结果：`0x2B908..0x10C980` 被 **0xE1078 字节**真实代码填满，正好到首段末尾；
首段前 `0x2B908` 字节（ELF 头/PLT/明文桩）保持不变。

### 62.3 保真验证与工具 **[Unicorn]**

- 直接调用解压器（`0x13168F`）与**完整 `DT_INIT` 模拟**（带 mmap/mprotect/munmap/
  open/read/close 钩子）两条路径输出**逐字节 0 差异**；
- 工具：`analysis/tools/unpack_x86.py`
  - 解析真 `PT_DYNAMIC`（`p_vaddr`→文件偏移）取 `DT_INIT`；
  - Unicorn x86_64 模拟 `DT_INIT`，实现 Linux x86_64 syscall（mmap/mprotect/munmap/
    open/read/write/close/exit），按页粒度装载 PT_LOAD；
  - 输出 flat image（vaddr==offset），并解析 `DT_SYMTAB`/`DT_HASH` 打印关键符号；
- 产物：`/tmp/libDexHelper-x86.unpacked.so`（解包镜像）；
  工具输出 `/tmp/x86_unpack_tool.so` 与前者解压区 **0 差异**；
- 解包后出现 `classes.dve`（`0xE46DE`）、`info.y`（`0xE4B79`）、`.edata`（`0xE4762`）、
  `libart`/`libdexfile`/`frida`/`xposed` 等字符串——x86 变体与 arm64 是同一套完整壳。

### 62.4 符号表与关键函数（1520 条，1012 个已定义函数） **[静态]**

| 符号 | 值 | 大小 | 说明 |
|---|---|---|---|
| `JNI_OnLoad` | `0x319F0` | `0x2535` | 主入口 |
| `load` (`_Z4loadiPvPKcm`) | `0x2F3C0` | `0x2AC` | DEX 装载 |
| `load23` | `0x2F720` | `0x115` | |
| `prepare_vmdex` | `0x2F9F0` | `0xA5` | |
| `DexFileLoader::Load` | `0x2FB80` | `0xC8` | 版本分派 |
| `LoadV26` / `LoadV28` | `0x2FC50` / `0x2FDA0` | 0x141 / 0x162 | |
| `LoadV34_BETA1` / `LoadV34_DP2` | `0x300C0` / `0x30280` | 0x1B3 / 0x13D | |
| `handle_exception_sig` | `0x30530` | `0x80` | 信号处理 |
| `elf__load` / `elf__unload` | `0xBC510` / `0xBCE20` | | YARA ELF 模块 |
| `_yr_scanner_scan_mem` | GOT `0x117020` | 8 | YARA 扫描入口 |
| `yr_modules_table` | `0x116FF0` | | |
| `TBOX0/1/2` | `0x113800/0x113400/0x113000` | 0x400 | SM4 T 表 |

### 62.5 与 arm64 的等价性 **[静态+Unicorn]**

- **SM4 同算法**：`TBOX0[0] = 0xd55b5b8e = L(τ(0))`（标准 SM4 T 表），
  `TBOX2/1/0` 三个表 + 第四个表 `0xEA3B0`；块函数从 `0x39EF0` 起，
  `bswap` + 四表查表，与 arm64 `sub_37CC4` 等价；
- **DEX 密钥同值**：arm64 的 16 B 静态常量 `66976ce8…9aa0`（`0xC2A50`）在 x86 中
  以**字节反转**形式出现在 va `0xE30D0`（`a09acb0f…9766`）。用
  `常量 ⊕ 包名` 对同一 `classes.jar` 首个 DEX 解密，得到 `dex\n035\0`
  （arm64 链路已验证），说明两架构共享同一密钥；
- **RC4 同钥**：`0x5BC40` 处 `c20 ^ c30 = aa3d0ac931aec5f251c7b709f8d36c97`，
  与 arm64 DVE `enc_type/0` 完全一致，且仅首次计算（flag 置 1）；
- **状态/检测面一致**：`PADDING`(`0x113C40`)、`dexflag`(`0x113C80`)、
  `vtag`(`0x113C90`)、`soflag`(`0x113E14`)、`libc_ptrace`(`0x113DF0`)；
  文件 I/O hook 层 `hd_open_filter`/`hd_read_so`/`hd_mmap_filter`/`hd_pread64_filter` 等；
  YARA 引擎符号齐全。

### 62.6 结论

- x86_64 变体不再是“未适配”：**解包、符号、SM4/RC4、YARA、检测面全部对齐 arm64**，
  同一 APK、同一 `classes.jar`、同一密钥与资源；
- 主要坑点：① 真 `PT_DYNAMIC` 要按 `p_vaddr` 读；② `p_filesz` 之外整页仍由文件支撑；
  ③ `DT_INIT` 尾部 `jmp [rsp-0x48]` 依赖调用者栈，模拟到“控制离开镜像”即可停；
- 剩余：x86 特有分支（`JNI_OnLoad`/`load`）的逐函数语义与实机验证；
  无 x86_64 设备时以静态 + Unicorn 结果为准。

---

## 63. x86 `JNI_OnLoad` 审计（`0x319F0`，2026-11-12）

### 63.1 基本信息 **[静态]**

| 项 | 值 |
|---|---|
| 地址/大小 | `0x319F0`，`0x2535` B |
| 签名 | `jint JNI_OnLoad(JavaVM* vm, void* reserved)`（`rdi=vm`, `rsi=reserved`） |
| 栈帧 | `0x998` B + `fs:[0x28]` canary（`0x33F20 → __stack_chk_fail`） |
| 返回值 | 成功 `0x10004`（`JNI_VERSION_1_4`）；`GetEnv` 失败 `-1` |
| 首个动作 | `vm->GetEnv(&env, 0x10004)`（JavaVM vtable `+0x30`） |
| 全局 | `javaVM`（bss `0x11A408`，GOT `0x111730`）、`g_sdkVer_forhook`（`0x1181A0`） |

阶段划分（按地址顺序）：

| # | 范围 | 内容 |
|---|---|---|
| A | `0x319F0-0x31B70` | `GetEnv`；`FindClass("com/secneo/apkwrapper/H")`；`RegisterNatives` **3 个**；`GetJavaVM → javaVM` |
| B | `0x31B71-0x31FB9` | 本地字符串/容器构造（`local@0x72670/0x72180/0x727F0/0x72850` + malloc/strcpy） |
| C | `0x31FBA-0x3210B` | `FindClass` H/AW；`PKGNAME` 静态字段 → 包名字符串 |
| D | `0x3213A-0x3252B` | SDK 属性：`ro.build.version.sdk`→`atoi`，`release`/`codename` 多次读取；SDK 23–30 跳表 |
| E | `0x3253B-0x326E8` | `PackageManager.MATCH_APEX`；`com.google.android.art`/`com.android.art`；`PackageInfo.getLongVersionCode` |
| F | `0x32765-0x32B8D` | `libdvm.so`/`libart.so` `access`；`persist.sys.dalvik.vm.lib(.2)`、manufacturer、yunos、`ro.product.cpu.abi`；读 `libc.so` 头 |
| G | `0x32BBC-0x32E57` | `sAppInfo`（ApplicationInfo）→ `sourceDir`/`dataDir`/`nativeLibraryDir` 拷贝；`getpid` |
| H | `0x32EE7-0x330E3` | 目录扫描：`opendir/readdir/atoi/readlink/strstr(".apk")/strncmp` |
| I | `0x330FF-0x33174` | 路径拼接；`sub_3BD60("libart.so")`、`sub_3BD60("libdexfile.so")` |
| J | `0x331C9-0x333FC` | `%s/%s/%s`、`classes.jar`/`classes.dex`/`classes.odex` 路径；3×`mkdir` |
| K | `0x33410-0x33564` | `/proc/self/cmdline`；`envc.push`；`access`/`remove` |
| L | `0x3357C-0x336C4` | 注册 `AW`（2 个方法）与 `H` 的 `(Ljava/lang/String;)Ljava/lang/String;` |
| M | `0x336CF` | `sub_33F30` 系统初始化（DVE/SharedPreferences/资源策略，见 §63.7） |
| N | `0x33721-0x33AF6` | 应用路径/字符串处理（malloc/strlen/strrchr）；`sub_69440` |
| O | `0x33B59-0x33EFF` | `sApp`（Application）→ `getApplicationInfo`；反射/容器 helper；`sub_69950`/`sub_6A0A0` |
| P | `0x33F0E-0x33F25` | 返回 `0x10004` |

### 63.2 注册的 native 方法 **[静态]**

`H`（首段，`ecx=3`）：

| 名称（原始字节） | 签名 | 实现 |
|---|---|---|
| `gah` | `(Ljava/lang/String;)I` | `0x2EA70` → `0x2EA90`（取 UTF，`%s%s` 路径拼接） |
| `sha` | `(Ljava/lang/String;I)V` | `0x2E670` → `0x2E690` |
| `he` | `(I)V` | `0x2EDF0` → `0x2EE10`（**上报/处置**：参数为 0 时 `kind=0x4000`、tag `0xb6a28e1e`、`0xFFF`） |

尾部再注册：

| 类 | 签名 | 实现 |
|---|---|---|
| `com/secneo/apkwrapper/AW` | `(Landroid/content/Context;Landroid/app/Application;)…` | `0x3DD80`（`ActivityThread.currentActivityThread` → `realApplication` 反射） |
| `com/secneo/apkwrapper/AW` | 第二个方法（同上注册路径） | `0x3DD80` |
| `com/secneo/apkwrapper/H` | `d`: `(Ljava/lang/String;)Ljava/lang/String;` | `0x3ED70`：**字符串解密器**（seed + hex + XOR，见 §64；与 arm64 的 `H.sn` 无关） |

- `0x2EE10` 与 arm64 `0x2DBC0` 同构：`config = *(GOT 0x111700)`，
  `test [config+0x14C], kind` 门控；通过后构造 `root`/`usb` 等消息上报。
- 三个短名（`gah`/`sha`/`he`）是壳自己的混淆命名；签名与实现一一对应。

### 63.3 SDK / ART 版本探测 **[静态]**

- `atoi(ro.build.version.sdk)` 得到 SDK int；
- `ecx = sdk - 23; cmp ecx, 7; ja default` → **SDK 23..30 跳表**（表在 `0xE3618`）：

| SDK | 目标 | 备注 |
|---|---|---|
| 23 | `0x321C7` | |
| 24 | `0x32514` | default 路径 |
| 25 | `0x3223E` | |
| 26 | `0x32514` | default |
| 27 | `0x322AB` | |
| 28 | `0x32316` | |
| 29 | `0x323E3` | |
| 30 | `0x324AC` | |

- 各分支把 SDK 映射为内部版本号 `0x1B/0x1C/0x1D`（27/28/29），与
  `DexFileLoader` 的 `LoadV26/V28/V34` 选择及 `g_sdkVer_forhook` 对应；
- 同时读取：`ro.build.version.release`、`ro.build.version.codename`、
  `persist.sys.dalvik.vm.lib(.2)`、`ro.product.manufacturer`、`ro.yunos.version(.release)`、
  `ro.product.cpu.abi`；
- 读 `/system/lib/libc.so` 头部（`fopen/fread/fclose`）判断 ELF 类型/架构。

### 63.4 环境与应用路径 **[静态]**

- `sAppInfo`（`ApplicationInfo`）→ `sourceDir`、`dataDir`、`nativeLibraryDir`；
- 目录扫描用 `opendir/readdir/readlink` 找 `*.apk`（`strncmp(".apk")`），
  处理 `sourceDir` 不可靠的情况；
- 路径模板：`%s/%s/%s`、`%s/%s` + `classes.jar`/`classes.dex`/`classes.odex`、
  `%s%s`；随后 3 次 `mkdir` 建缓存目录；
- `/proc/self/cmdline` 读进程名（`fscanf`），与预期包名/进程名 `strcmp`；
- `envc.push` 临时文件 → `access` → `remove`（启动清理）。

### 63.5 运行时库定位 `sub_3BD60` **[静态]**

`sub_3BD60`（`0x3BD60`）被 `JNI_OnLoad` 用 `"libart.so"`/`"libdexfile.so"` 调用，
内部做三件事：

1. 扫 `/proc/self/maps`（匹配 `r-xp`/`r--p`/`--xp`、`%lx-%lx `）定位已加载库的基址；
2. 通过 `ServiceManager.getService("package")` → `IPackageManager.transact`
   + `Parcel` 读写取 `PackageInfo`（不依赖 Java 层 API）；
3. 反射工具：`getFieldValue`/`setFieldValue`、`realApplication`、
   `com/secneo/apkwrapper/H`/`AW` 的字段读写。

### 63.6 `sub_33F30`：DVE / SharedPreferences 初始化 **[静态]**

`sub_33F30`（`0x33F30`，栈 `0x958`）由 `JNI_OnLoad` 在 `0x336CF` 调用，关键内容：

- 路径/文件：`classes.dve`、`RES_RULE`、`assets/RES_RULE`、`%s%s/%s/%s`、
  `/proc/%d/maps`、`%s32/.a`；
- 品牌判断：`ro.product.brand` + `Huawei`/`Honor`（决定 hook/路径差异）；
- SharedPreferences 链路：`android/app/ContextImpl`、`sSharedPrefs`、
  `Landroid/util/ArrayMap;`、`android/app/SharedPreferencesImpl`、
  `startLoadFromDisk`，配合 `entrySet/iterator/Map$Entry` 反射遍历；
- 另有 `java/lang/Object`、`toString`、`equals` 等反射基础方法。

即 x86 与 arm64 一样，在 `JNI_OnLoad` 阶段完成 DVE 策略读取（`classes.dve`/`RES_RULE`）
和 SharedPreferences 装载劫持。

### 63.7 与 arm64 对照 **[静态]**

| 项 | x86 | arm64 |
|---|---|---|
| 注册类 | `com/secneo/apkwrapper/H`、`AW` | 同 |
| `H` 的 String→String 方法 | `0x3ED70`（名字 `d`，字符串解密器，§64） | `0x4B4E0`（`H.sn`，返回 int，校验 INFO） |
| VM/SDK 全局 | `javaVM`、`g_sdkVer_forhook` | 同 |
| 属性/路径 | SDK、release/codename、dalvik.vm.lib、sourceDir/dataDir、classes.jar/dex/odex | 同 |
| 上报门控 | `config+0x14C` + kind（`0x4000`/`0xb6a28e1e`） | `0x2DBC0` + kind（frida/xposed/root） |
| 运行时定位 | `/proc/self/maps` + binder PackageInfo + 反射 | 同思路 |

### 63.8 结论

- x86 的 `JNI_OnLoad` 是标准的 Bangcle 初始化大函数：**注册 native → 探测 SDK/ART →
  收集应用路径/属性 → 定位 libart/libdexfile → 建目录/清理 → 初始化 DVE 与
  SharedPreferences 劫持**；字符串基本明文，静态可读性远高于 arm64 的 CFF 混淆段；
- 版本分支集中在 SDK 23–30；`g_sdkVer_forhook` 供后续 hook 选择偏移；
- `H` 的 `(I)V` native（`0x2EDF0`）是调试/错误上报触发器，参数为 0 时按
  `kind=0x4000`、`tag=0xb6a28e1e` 走上报/处置路径，与 §60/§61 属同一套机制；
- 待办：`sub_33F30` 的 DVE 分支细节与 `load/load23` 的逐函数语义。

---

## 64. x86 `H.d` 字符串解密器审计（`0x3ED70`，2026-11-12）

### 64.1 注册与方法名 **[静态]**

- 类：`com/secneo/apkwrapper/H`；
- 方法名：`"d"`（rodata `0xE4356`，字节 `64 00`）；
- 签名：`(Ljava/lang/String;)Ljava/lang/String;`；
- 实现：`0x3ED70`；`RegisterNatives` 在 `0x336B5`（1 个方法）。

> 更正：§63 早期按 arm64 习惯称其为 `H.sn`。实际注册名是 **`d`**；
> arm64 的 `H.sn` 是 `(String)int` 的 `info.y` 更新入口，二者不同。

### 64.2 算法还原 **[静态+Unicorn]**

```
jstring H_d(JNIEnv* env, jobject thiz, jstring s) {
    const char* in = env->GetStringUTFChars(s, 0);
    size_t n = strlen(in);
    size_t outlen = (n - 1) >> 1;
    char* buf = malloc(outlen);
    memset(buf, 0, outlen);

    // 输入格式: [1 字节 seed][大写 hex 密文]，hex 从 index 1 开始
    for (i = 1; i + 1 < n; i += 2)
        buf[(i - 1) / 2] = (hexval(in[i]) << 4) | hexval(in[i + 1]);

    uint8_t seed = (uint8_t)in[0];
    uint8_t ks[16];
    for (j = 0; j < 16; j++) ks[j] = CONST[j] ^ seed;
    for (k = 0; k < outlen; k++) buf[k] ^= ks[k % 16];

    env->ReleaseStringUTFChars(s, in);
    if (!intern_mid)
        intern_mid = env->GetMethodID(env->FindClass("java/lang/String"),
                                      "intern", "()Ljava/lang/String;");
    jstring t = env->NewStringUTF(buf);
    jstring r = env->CallObjectMethod(t, intern_mid);
    env->DeleteLocalRef(t);
    return r;
}
```

- `CONST`（va `0xE32A0`，16 B）：
  `4e a4 f2 3d 98 17 8c 0e c1 29 b7 6f d5 c2 e4 f0`；
- `String.intern()` 的 `jmethodID` 缓存在全局 `0x11A648`；
- 纯内存操作：无文件、无网络、无系统属性；
- `malloc` 失败时直接返回原输入字符串（`r15` 未被覆盖）。

### 64.3 边界与实现细节 **[静态]**

| 项 | 行为 |
|---|---|
| hex 表 | 仅 `"0123456789ABCDEF"`；小写/非 hex 字符无校验，`strchr` 返回 NULL 后差值会得到垃圾字节 |
| seed | 输入第 1 个字符，只参与 keystream，不参与 hex |
| 最短输入 | `n < 2` 时跳过解码 |
| 输出长度 | `(n-1)>>1`，并在 `buf[outlen]` 写 NUL |
| keystream | 16 字节周期，`CONST[j] ^ seed` |
| 返回值 | `NewStringUTF(buf)` 后调用 `String.intern()`，返回 interned 引用 |
| SSE 分支 | `0x3EF1E` 的向量块在 `n>=32` 时被 `(n-1)>=0x10` 检查恒跳回标量路径，**实际不可达** |

### 64.4 验证 **[Unicorn]**

用伪 `JNIEnv` 函数表 + libc 桩（`GetStringUTFChars`/`ReleaseStringUTFChars`/
`NewStringUTF`/`FindClass`/`GetMethodID`/`DeleteLocalRef`，以及
`strlen`/`malloc`/`memset`/`free`/`__strchr_chk`/`CallObjectMethod`）执行真实函数：

| 用例 | 结果 |
|---|---|
| 12 B payload（`Hello,World!` 的 hex） | 输出 `47 80 df 10 b6 7a 9a 20 f2 04 92 0f`，与 Python 模型逐字节一致 |
| 40 B payload（`00..27`） | 40 字节全部与模型一致（含 16–31、32–39 段） |

结论：算法、常量、周期、边界均已验证，无歧义。

### 64.5 意义

- `H.d` 是 Java 层的**字符串解密入口**：壳用它把常量表里的
  `seed + hex` 字符串还原成路径/类名/URL 等，返回 `intern` 后的 String；
- 与 arm64 的 `H.sn`（`info.y` 更新，返回 int）同宿主、不同语义；
- 该方法不涉及落盘，因此不存在“解密后写文件”的副作用；需要落盘的是
  `sub_33F30` 的 DVE 分支与 `H.sn`（arm64）。

---

## 65. 功能点清单（基于逆向结果，2026-11-12）

> 按能力域分组。每条给出入口/实现、行为、开关/条件与证据章节；
> `[验证]` = 有复现/引擎级证据，`[静态]` = 代码级还原，`[实测]` = 设备/样本观测。

### 65.1 载荷自解密与加载

| 编号 | 功能点 | 入口/实现 | 行为 | 证据 |
|---|---|---|---|---|
| F-01 | 双 `PT_DYNAMIC` 欺骗 | `p_offset` 诱饵 / `p_vaddr` 真表 | 静态工具读到只有 NEEDED/SONAME 的假表；linker 按 `p_vaddr` 读到真表 | §2、§12 `[静态]` |
| F-02 | maps 自检 | `0x108380 → 0x1081DC` | 校验自身映射，失败 `exit_group(94)` | §16 `[实测]` |
| F-03 | `DT_INIT` 自解密 | `0x108098`；LZSS `0x108914` | mmap RWX → 位流 LZSS 解压（描述符 `0x108B48`：0xB8B00/0x53EDE）→ 4 字节 XOR → 重定位 → icache flush → mprotect | §16–§18 `[验证]` |
| F-04 | 构造器链 | `DT_INIT_ARRAY=0x2D230` | 初始化后 `dlsym("JNI_OnLoad")` → `0x2F7F0` | §13 `[静态]` |
| F-05 | 通用脱壳器 | `unpack.py` | 不硬编码样本常量，执行原 `DT_INIT`；多 so 验证 | §17–§19 `[验证]` |

### 65.2 DEX 容器、解密与加载

| 编号 | 功能点 | 入口/实现 | 行为 | 开关/条件 | 证据 |
|---|---|---|---|---|---|
| F-10 | `classes.jar` 容器 | `dexdata0 @0x27BC0` | 伪 DEX 头 + `0x1000` 段头 + 14 条 `{off,size}` 记录 | 固定 | §28–§33 `[验证]` |
| F-11 | DEX 解密 | SM4 key schedule `0x37B78`、块函数 `0x37CC4` | 标准 SM4-ECB；`key16 = so@0xC2A50 ⊕ 包名前16B`；每个 DEX 仅前 `0x20000` 加密，其余明文 | 包名 | §39 `[验证]` 14/14 |
| F-12 | 容器解析/复现 | `fdex_unpack.py`、`sm4.py` | 14 个 DEX 输出，MD5 与动态捕获一致 | — | §39 `[验证]` |
| F-13 | DEX 版本分派 | `DexFileLoader::Load`；`LoadV26/V28/V34_BETA1/V34_DP2` | 按 SDK/ART 版本选择加载实现 | SDK 23–30 | §13、§63 `[静态]` |
| F-14 | 校验绕过 | `MethodVerifier::VerifyClass → 0x592A8`（恒返回 0）；`Runtime` 校验标志清零 | 关闭 ART 类校验 | 启动时 | §20 `[实测]` |
| F-15 | DEX 装载接口 | `load 0x2E048`、`load23 0x2E3C4`、`prepare_vmdex 0x2E6C0`、`transfer 0x2DFEC` | 供 Java/JNI 调用的装载入口 | — | §13、§46 `[静态]` |
| F-16 | `classes.dve` 版本戳 | 24 B `vtag`；状态 0/1/2 → `sub_41F80` | `MD5(so@0xEAC90 64B) + fstat(oat).st_ctim`；决定是否重建缓存/重写 `.edata` | 安装/升级 | §40 `[静态+实测]` |

### 65.3 DVE 透明文件加密与 I/O 拦截

| 编号 | 功能点 | 入口/实现 | 行为 | 开关/条件 | 证据 |
|---|---|---|---|---|---|
| F-20 | `.edata` 策略解析 | `enc_type/N` + 路径规则 | 记录加密类型与包含/排除路径（`!`=排除） | `.edata` 内容 | §42 `[静态]` |
| F-21 | `enc_type/0` 加密 | 标准 RC4 | 16 B key = `so@0xEADF8 ⊕ so@0xC2960` = `aa3d…6c97`；文件级 RC4 | enc_type=0 | §43 `[验证]` 5 个 XML |
| F-22 | `enc_type≠0` 加密 | 前 `0x20000` RC4 + 其余 XOR `0xAC` | 混合模式；`offset≥0x20000` 全 XOR | enc_type≠0 | §44 `[验证]` 6/6 |
| F-23 | 规则下发 | `assets/RES_RULE` XOR `"KEY_RES_ENC"` | 服务端下发的加密路径策略；当前 APK 无该资源 | 服务端 | §42 `[静态]` |
| F-24 | 文件 I/O hook 层 | x86 符号 `hd_open_filter`/`hd_read_filter`/`hd_mmap_filter`/`hd_pread64_filter`/`hd_lseek_filter`/`hd_close_filter`/`hd_readlink_filter` + `hd_*_so` | 按路径透明加解密；`hd_*_stub` 为跳板 | 被保护路径 | §62、§63 `[静态]` |
| F-25 | SharedPreferences 劫持 | `sub_33F30`（x86） | `ContextImpl/sSharedPrefs/SharedPreferencesImpl/startLoadFromDisk` + `ArrayMap` 反射遍历 | 启动 | §63 `[静态]` |

### 65.4 检测规则库 `info.y`（编译后的 YARA）

| 编号 | 功能点 | 入口/实现 | 行为 | 开关/条件 | 证据 |
|---|---|---|---|---|---|
| F-30 | 规则释放 | `sub_4B4F0` | APK `assets/info.y` → `/data/user/0/<pkg>/.cache/info.y` | 首次/更新 | §41、§46 `[静态]` |
| F-31 | 规则加载 | `sub_4E9F0` → `0x99A7C`（`get_hash` `0x991F0` + `fopen`）→ parser `0x7D924` | INFO 容器校验（MD5 = `body[0x16:]`）+ 建 arena | 文件存在 | §46、§50 `[验证]` |
| F-32 | 容器格式 | `INFO-` + MD5 + count + 12×`{off,flags,size}` + 214 条 `yr_arena_ref_to_ptr` 重定位 | 自定义序列化，非标准 `.yar` | — | §51 `[验证]` 10/10 |
| F-33 | 规则对象 | builder `0x9907C` | 生成 `0x50` B 规则句柄：+0 arena、+8..+0x38 段、+0x40..+0x48 计数 | — | §52 `[验证]` 15/15 |
| F-34 | YARA 引擎 | `_yr_scanner_scan_mem`（`0xEDFF0→0x9BF94`）、`yr_modules_table`、`elf__*`、`rb_null` | 静态链接的完整 YARA + ELF 模块 | — | §47、§58–§59 `[验证]` |
| F-35 | 规则集 | 9 rules / 21 strings | roothide/edxposed/xposed/fridasig/yarfahook/taichi/fupk3/youpk/fart | — | §53 `[验证]` |
| F-36 | condition VM | executor `0x81DFC`、分派 `0xC9CA4` | `0x1C` 规则块、`0x0D` push 字符串、`0x16` 命中、`0x2F/0x31` 跳转、`0x01/0x02` AND/OR、`0x1D` 上报 | — | §54–§55 `[验证]` |
| F-37 | 扫描对象收集 | maps 扫描 → `sub_85128` | open+fstat+malloc+read 整个 `.so`（非 mmap、非 ELF 解析），`madvise(SEQUENTIAL)` | 进程已加载 .so | §46、§48 `[静态]` |
| F-38 | 扫描调度 | worker `0x4F680` → matcher `0x9C024` | 逐文件调用扫描器；每条规则的条件由 VM 执行 | — | §46、§59 `[验证]` |
| F-39 | 规则热更新（arm64） | JNI `H.sn(String):int` `0x4B4E0`（`RegisterNatives 0x32BE0`） | 校验传入 INFO 后覆盖 `.cache/info.y`；静态代码中未发现调用者 | Java 调用 | §49 `[静态]` |
| F-40 | 命中处置 | callback `0x4F414`（mode 1）→ `0x2DBC0` | 规则名分类 `frida/xposed/root/other` → 配置位门控 → 文件型上报 `0x2D8F4`/`0x2D5E4`（`fopen/flock`，非网络） | `config+0x14C` & kind | §60 `[静态]` |
| F-41 | 实扫结论 | `scan_rules.py` / `emu_yara_scan.py` | 设备 56 个业务 so **0/9 命中**；测试 so 引擎级 **14/14** 一致 | — | §56–§59 `[验证]` |

### 65.5 反调试、完整性与自毁

| 编号 | 功能点 | 入口/实现 | 行为 | 开关/条件 | 证据 |
|---|---|---|---|---|---|
| F-50 | 信号处置 | `handle_exception_sig` `0x2F1A4` | SIGTRAP 走特殊反调试路径；其它信号记录后自毁 | 信号类型 | §61 `[静态]` |
| F-51 | 硬终止原语 | `0x384F0` | **裸 `svc` 的 `kill(pid, SIGKILL)`**（`x8=129`，无 libc 导入），失败写 errno | — | §61 `[静态]` |
| F-52 | 自毁调用点 | 7 处 `bl 0x384F0` | 统一模板 `getpid → kill → _exit(3)`（`0x518BC` 为 `exit(0)`）：YARA 处置、信号处理、完整性检查、反调试子进程等 | 分支命中 | §61 `[静态]` |
| F-53 | 内联 syscall 变体 | `0x5137C`/`0x51588`/`0x518A4`/`0x54D98`/`0x558F4` 等 | 内联 `kill`（含 `kill(-1,SIGKILL)`）、`getpid`、`read`，**绕过 libc hook** | — | §61 `[静态]` |
| F-54 | 反调试子进程 | `sub_51024`/`sub_552A4`/`sub_559C4`/`sub_55A84` | `fork/pipe/execl/select`；扫 `/proc/%ld/{cmdline,net,task,status}`；`waitpid` 监控子进程，异常即同归于尽 | — | §61 `[静态]` |
| F-55 | 预杀日志 | `__android_log_print(5,"LOG.OUT","%d, %x, %x",…)` | 自毁前记录 pid 与常量 tag（`0xb6a286xx` 族） | 触发分支 | §61 `[静态]` |
| F-56 | 配置门控 | `[config+0x14C]` | 按 kind 位掩码决定某类检测是否启用/上报；bit5(`0x20`)=1 时跳过自毁 | 配置对象 | §60、§61 `[静态]` |
| F-57 | ptrace 检测 | `libc_ptrace`（GOT/全局） | 检测调试器附着 | 运行期 | §62 `[静态]` |

### 65.6 Java/JNI 交互与启动流程

| 编号 | 功能点 | 入口/实现 | 行为 | 证据 |
|---|---|---|---|---|
| F-60 | `JNI_OnLoad` | arm64 `0x2F7F0`；x86 `0x319F0` | `GetEnv` → `RegisterNatives` → 环境/路径/运行时初始化 | §13、§63 `[静态]` |
| F-61 | native 注册（x86） | `H`: `gah`/`sha`/`he`/`d`；`AW`: 2 个 | `H.d` 字符串解密；`H.he` `(I)V` 上报触发（`kind=0x4000`/tag `0xb6a28e1e`）；`AW` 走 `ActivityThread.currentActivityThread` + `realApplication` | §63、§64 `[静态+验证]` |
| F-62 | SDK/ART 探测 | x86 `JNI_OnLoad` | `ro.build.version.sdk` → `atoi`，SDK 23–30 跳表（`0xE3618`）；release/codename、`persist.sys.dalvik.vm.lib(.2)`、APEX `com.google.android.art`/`com.android.art`、`PackageInfo.getLongVersionCode` | §63 `[静态]` |
| F-63 | 应用信息/路径 | x86 `JNI_OnLoad` | `sAppInfo` → `sourceDir`/`dataDir`/`nativeLibraryDir`；`classes.jar/dex/odex` 路径；3×`mkdir`；`/proc/self/cmdline`；`*.apk` 扫描；`envc.push` 清理 | §63 `[静态]` |
| F-64 | 运行时定位 | x86 `sub_3BD60` | `/proc/self/maps`（`r-xp/r--p/--xp`）找 libart/libdexfile 基址；`ServiceManager/IPackageManager.transact` 取 `PackageInfo`；反射 `getFieldValue/setFieldValue` | §63 `[静态]` |
| F-65 | 字符串解密器 | x86 `H.d` `0x3ED70` | 输入 `[seed][大写hex]`；hex 解码后 XOR `CONST^seed`（16B 周期）；`String.intern()` 返回 | §64 `[验证]` |
| F-66 | VM/SDK 全局 | `javaVM`@`0x11A408`、`g_sdkVer_forhook`@`0x1181A0`（x86） | 保存 JavaVM 与 SDK 版本，供后续 hook/反射使用 | §63 `[静态]` |
| F-67 | 配置初始化 | x86 `sub_33F30` | `classes.dve`/`RES_RULE`/`assets/RES_RULE`、品牌 Huawei/Honor、SharedPreferences 装载劫持 | §63 `[静态]` |

### 65.7 x86_64 变体

| 编号 | 功能点 | 入口/实现 | 行为 | 证据 |
|---|---|---|---|---|
| F-70 | 双 `PT_DYNAMIC` | `p_offset=0x1178F0` 诱饵 / `p_vaddr=0x111498` 真表（文件 `0x110498`） | `DT_SYMTAB=0x2C0`、`DT_HASH`（1520 符号）、`DT_INIT=0x131098` | §62 `[静态]` |
| F-71 | `DT_INIT` 原地解压 | `0x131098`；解压器 `0x13168F` | `mmap` 复制 `0x2B908` 处 `0x61A85` B 压缩体；原地 LZSS 解压为 **0xE1078** B（到段尾）；7 bit/字节 + literal/LZ 匹配 | §62 `[验证]` 0 差异 |
| F-72 | 页粒度映射坑 | 段 1 `p_offset/p_vaddr` 差 `0x1000` | `p_filesz` 之外整页仍由文件支撑 → TBOX/PADDING/vtag/密钥常量位于 `0x113000+` 而非 bss | §62 `[静态]` |
| F-73 | 同钥/同引擎 | SM4 TBOX `0x113000/0x113400/0x113800` + 第四表 `0xEA3B0`；块函数 `0x39EF0`；RC4 `0x5BC40`；YARA 符号齐全 | SM4 常量在 x86 以字节反转存于 `0xE30D0`；RC4 同钥 `aa3d…6c97`；`classes.dve/info.y/.edata` 字符串齐全 | §62 `[验证]` |

### 65.8 触发条件/开关汇总

| 开关 | 位置 | 作用 |
|---|---|---|
| `config+0x14C` kind 位掩码 | 运行时配置对象 | 某类检测是否启用/上报 |
| `config+0x14C` bit5 (`0x20`) | 同上 | 为 1 时跳过自毁，仅上报 |
| `.edata` `enc_type/N` | 应用数据目录 | 选择 RC4 变体（0 / ≠0） |
| `.edata` 路径规则 | 同上 | 包含/排除加密路径（`!`=排除） |
| SDK 23–30 | 系统属性 | 选择 ART/DexFileLoader 分支与 hook 偏移 |
| `persist.sys.dalvik.vm.lib(.2)` / APEX | 系统属性/包管理 | 判断 dalvik/art 与 ART 模块版本 |
| `/proc/self/cmdline` | 进程信息 | 进程名匹配（决定是否在子进程生效） |
| `info.y` 规则条件 | 规则库 | 9 条规则，命中后进入处置链 |
| 路径后缀 `.so` | maps 扫描 | 仅扫描已加载的 native 库 |

### 65.9 未闭环项（与 §45.7 同步）

1. `config+0x14C` 的**运行时默认值**（哪些类别默认启用、bit5 默认值）。
2. `0x2DBC0` 文件上报后的服务端二次拉取路径。
3. `manifest.mf` / `rsa.sig` 的完整性校验是否在 so 内执行及失败行为。
4. 服务端 `RES_RULE` / `enc_type/16` 的真实下发样本（当前 APK 缺失）。
5. x86 `load/load23` 逐函数语义（`sub_33F30` 已审计 §66）。
6. x86_64 实机验证（当前以静态 + Unicorn 为准）。

---

## 66. x86 `sub_33F30` 审计（DVE + SharedPreferences + 反调试启动，2026-11-12）

### 66.1 概况 **[静态]**

| 项 | 值 |
|---|---|
| 范围 | `0x33F30–0x35746`（`0x1816` B） |
| 栈帧 | `0x958` B；canary `[rsp+0x950]`；尾声 `0x3571E–0x35746`，失败跳 `0x39A5D` |
| 提前返回 | `0x34D58`（一条分支的正常出口） |
| 调用者 | `JNI_OnLoad` `0x336CF`（唯一调用点），`rdi = JNIEnv*` |
| 角色 | `classes.dve`/vtag 初始化 + `RES_RULE`/`.edata` 策略 + SharedPreferences 强制加载 + 反调试/看门狗线程 + `nop` native 注册 |

阶段划分：

| # | 范围 | 内容 |
|---|---|---|
| A | `0x33F30–0x340D8` | 取全局配置；`%s%s`、`%s%s/%s/%s`、`%s%s/%s` + `classes.dve` 构造路径；memset |
| B | `0x34100–0x342B8` | 构造 odex 路径（`/%s/%s/%s` + `oat`）；扫 `/proc/%d/maps`，`fgets/strstr/strncmp("dex")`，`sscanf` 提取映射文件路径 |
| C | `0x342C0–0x343D8` | `__open_2` + `fstat` 取 ctime；拷贝 64 B seed（`GLOBAL vtag@0x113C90`）；`sub_48720/sub_48880` 计算 MD5；`vtag+0x10 = ctime` |
| D | `0x343E6–0x3447E` | `access(classes.dve)`；缺失 → `sub_48630` 建父目录 + `fopen("wb")` + `fwrite(vtag,1,0x18)`（状态 2） |
| E | `0x34A35–0x34BE0` | 存在 → `fread` 24 B；`pcmpeqb` 比对前 16 B MD5 + 比对 ctime；匹配状态 0；不匹配重写 |
| F | `0x3448E–0x345AC` | `dexflag` 位（bit2 `0x4`→`sub_44C50`，bit4 `0x10`）；名称 `RES_RULE` → 读 `assets/RES_RULE`，用 `"KEY_RES_ENC"`（11 B）循环 XOR 解密 |
| G | `0x345AC–0x345CF` | `sub_45090` 写 `.edata` 策略（`/data/user/0|1/<pkg>/`、`/data/data/<pkg>/`） |
| H | `0x345CF–0x34682` | SDK 19–23 时读 `ro.product.brand`，与 `Huawei`/`Honor` 比较后分支 |
| I | `0x34682–0x34A11` | SharedPreferences：`ContextImpl.sSharedPrefs`（ArrayMap）→ `get` → `entrySet/iterator`；对每个 `SharedPreferencesImpl` 调 `startLoadFromDisk()` |
| J | `0x34C95–0x34D58` | 构造 `"pthread_create"`；`sub_4E740(libc.so, "pthread_create")` 解析/校验；失败 → `getpid` + `kill(SIGKILL)` + `_exit(3)` |
| K | `0x34D6F–0x351C3` | 32/64 路径字符串（`%s32/.a`、`%s64/.a`）；`RegisterNatives(H, (String)I → _Z3nopPc)`；构建 7 项线程函数表 |
| L | `0x351C3–0x35255` | 按标志选择表项；`pthread_create(0x4EAD0)` + `sleep(1)` 重试 |
| M | `0x3529B–0x35399` | `prctl(PR_SET_DUMPABLE,1)`；`pipe×3`；`fork`；父/子关 fd；`sub_593D0`；`pthread_create(0x5AB00)` |
| N | `0x353FF–0x3543B` | `ptrace(PTRACE_ATTACH, pid)` → `wait` → `ptrace(PTRACE_DETACH, pid)` |
| O | `0x354FE–0x355CF` | 第二组 pipe/fork；`sub_59C20`/`sub_59F60`/`sub_5ABC0` |
| P | `0x35632–0x356B5` | malloc/strncpy；`pthread_create ×2` + sleep；`sub_40920` |
| Q | `0x356CA–0x35746` | `FindClass(H)`、`NewGlobalRef`；尾声 |

### 66.2 vtag / `classes.dve` 语义 **[静态]**

- seed：`GLOBAL vtag @0x113C90`（64 B，符号大小 0x40）；
- `vtag[0..15] = MD5(seed64)`（`sub_48720`，内部调用 `sub_48880` 两次）；
- `vtag[0x10..0x17] = fstat(odex 映射文件).st_ctim.tv_sec`（`0x343d8`）；
- `classes.dve` 固定 **24 B**：前 16 B MD5 + 后 8 B ctime；
- 存在性/一致性判定：
  - 文件缺失 → 建父目录并写入（状态 **2**，`0x34483`）；
  - 前 16 B 与 ctime 均匹配 → 状态 **0**（`0x34B3B`）；
  - MD5 或 ctime 不匹配 → 重写 24 B（状态沿用/置位后传给 `sub_45090`，`0x34B51` 分支）。
- `/proc/self/maps` 扫描目标：匹配行含 odex 路径且以 `dex` 结尾，去掉 `r-xp` 等后缀后 `sscanf` 取文件名。

### 66.3 `RES_RULE` / `.edata` **[静态]**

- `dexflag`（`0x113C80`）：
  - `[+3] & 0x4` → `sub_44C50`：构造 `.aid` 路径，读取 `ro.build.fingerprint` / `ro.product.build.fingerprint`；
  - `[+3] & 0x10` → 作为标志传入 `sub_45090`。
- 配置项名称 `[r13+0x10]` 与 `"RES_RULE"` 比较；命中时：
  1. `sub_490B0(assetMgr, "assets/RES_RULE", &out, 0)` 取资源；
  2. 用 11 字节 `"KEY_RES_ENC"` 循环 XOR 解密；
  3. 数据指针/长度写回配置结构（`+0x10`/`+0xC`）。
- `sub_45090` 按 `/data/user/0/%s/`、`/data/user/1/%s/`、`/data/data/%s/` 写 `.edata`。
- `sub_490B0` 内含 `!/sdcard/`、`/**/`、`/sdcard/` 路径规则处理（DVE 排除/规范化）。

### 66.4 SharedPreferences 强制加载 **[静态]**

```
ContextImpl.sSharedPrefs (ArrayMap)
  → ArrayMap.get(<name>)
  → entrySet()/iterator()
  → for each value:
        if value is SharedPreferencesImpl:
            value.startLoadFromDisk()
```

- 目的：在 DVE 文件 hook 生效后，强制所有 SharedPreferences 走一次磁盘加载/解密；
- 迭代期间大量 `DeleteLocalRef`（`0x34BEF–0x34C8F`），避免局部引用表溢出；
- `sSharedPrefs` 为空/类型不符时走 `0x34C95` 分支。

### 66.5 品牌 / SDK 门控 **[静态]**

- `SDK-19..23`（`add ecx,-0x13; cmp ecx,4`）才进入品牌分支；
- `ro.product.brand` 与 `Huawei`（6 B）、`Honor`（5 B）`strncasecmp`；
- 厂商命中/未命中分别走不同后续（影响 SharedPreferences/路径处理分支）。

### 66.6 `pthread_create` 解析与自毁 **[静态]**

- `0x34C9C` 在栈上拼出 `"pthread_create"`（前段有干扰常量，随后逐字节覆盖）；
- `sub_4E740(?, "libc.so", "pthread_create")`：
  - 内部扫 `/proc/self/maps`（`sub_3B620`）、解析 ELF 符号（`sub_3ADF0`）；
  - 返回 1 表示解析成功；
- 成功后执行一段混淆常量运算；结果为 0 时：
  `getpid` → `sub_3ADB0`（**裸 `syscall` `kill(pid, SIGKILL)`**，x86_64 `__NR_kill=62`）→ `_exit(3)`；
- `0x3ADB0` 是 arm64 `0x384F0` 的 x86 对应物。

### 66.7 反调试 / 看门狗线程 **[静态]**

- **7 项线程函数表**（`0x35148–0x351BC`）：
  `0x4ED20`、`0x4EE20`、`0x4F110`、`0x50150`、`0x50C00`、`0x511C0`、`0x52690`；
  按标志位 `flag & 1` 通过 `call [table + flag*8]` 选择入口（32/64 位路径差异）；
- **`nop` native**：向 `com/secneo/apkwrapper/H` 注册 `(Ljava/lang/String;)I`，
  实现为 `_Z3nopPc` = `0x305B0`（单条 `ret`）——占位/对抗性注册；
- **看门狗线程**：`pthread_create(0x4EAD0)`，失败 `sleep(1)` 重试；
- **父子进程 + ptrace**：
  - `prctl(PR_SET_DUMPABLE=4, 1)`；
  - `pipe ×3` → `fork`；父进程关子端 fd 并 `sub_593D0`，子进程关父端；
  - `pthread_create(0x5AB00)`，参数结构 `{fd, pid, …}`（`0x35311` malloc 0x10）；
  - `ptrace(PTRACE_ATTACH=16, pid)` → `wait` → `ptrace(PTRACE_DETACH=7, pid)`；
  - 第二组 `pipe×2/fork` + `sub_59C20`/`sub_59F60`/`sub_5ABC0`；
  - 任何一步失败（如已被其它调试器 attach）即进入检测/自毁路径。

### 66.8 与 arm64 对照 **[静态]**

| 能力 | x86 | arm64 |
|---|---|---|
| vtag/`classes.dve` | seed `0x113C90` + fstat ctime | seed `0xEAC90` + fstat ctime（§40） |
| `.edata`/`RES_RULE` | `sub_490B0`/`sub_45090` | 同语义（§42） |
| 反调试子进程 | `sub_33F30` 内 fork/pipe/ptrace + 看门狗线程 | `sub_51024`/`sub_552A4`/`sub_559C4`/`sub_55A84`（§61） |
| 硬终止 | `0x3ADB0`（syscall 62） | `0x384F0`（syscall 129） |
| SharedPreferences | 集中在本函数 | 同族逻辑（符号混淆） |

### 66.9 未闭环 / 推断项

1. `r14d` 状态值在“不匹配重写”分支的精确赋值（0 vs 1）需动态确认；
2. `sub_45090` 的 `edx` 参数语义与 `.edata` 写入的最终内容；
3. `0x34D89`/`0x34D98` 的 32/64 路径字符串未解混淆
   （`0fduc2ecwb1wpr1okxoclkwq/dobeneg{b`、`kxoclkwq/dobeneg{b`，配套 `%s32/.a`、`%s64/.a`）；
4. `sub_40920` 与 `sub_59C20/59F60/5ABC0` 的线程体内部逻辑；
5. 设备实跑验证（当前静态还原）。
