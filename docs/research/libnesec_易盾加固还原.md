> **来源**：`<external-research-dir>/sampleb/libnesec_全功能还原文档.md`（2026-11-20/21）。
> **定位**：ForgeMirror 参照样本 B（网易易盾），与 `libDexHelper_架构还原.md`（参照样本 A）并列。
> **证据级别映射**：原文 `观测`→`V`，`代码`→`S`，`推断`→`I`，`未知`→`U`（定义见 `docs/设计文档.md` §17.1）。
> **产物位置**：文中 `artifacts/...` 均相对 `<external-research-dir>/sampleb/`。运行时 dump、伪代码与等价 C 代码属外部研究产物，**不进入本仓库**（根 `artifacts/` 被 git 忽略；`docs/实现原则.md` §2 禁止打包原厂反编译产物）。
> **吸收边界**：只吸收检测能力与方法论；不复刻 `exit_group` 响应、7-bit 字符串混淆和本构建不可达的证书链，取舍见 `docs/设计文档.md` §17.9。

---

# libnesec.so 全功能还原文档

- 日期：2026-11-20
- 目标：网易易盾加固 native 库 `libnesec.so`（SONAME `libsecexe.so`）
- 样本 SHA-256：`8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff`
- 运行时版本：易盾 `7.6.3_996`；APK `com.example.sampleb`
- 本文件回答两件事：
  1. `libnesec.so` 里到底有哪些功能、如何连接；
  2. 哪些行为可以等价复现，复现代码在哪里。

> 口径：本文是**行为等价还原**，不是宣称拿到网易易盾原始源码。
> 所有结论标注证据：`观测`（设备/内存）、`代码`（反编译/反汇编）、`推断`、`未知`。

---

## 0. 方法与证据链

1. **静态**：原库为 stripped ELF，`.gnu.fragment` 是加密段（900,720 B），静态反编译只能看到加载器/工具函数（160 个）。
2. **运行时内存 dump**：Frida spawn 后在 `libnesec.so` 加载完成时 dump 全部可读段，得到 1,167,360 B 运行镜像。
3. **差分**：与磁盘文件对比，命中：
   - `0x190..0xf4000`：885,108 B 被解密（真实代码 + 字符串表）
   - `0xdc000..0xf4000`（bss 尾）：77,912 B 被写入
   - `0x109b00+`（数据段）：3,925 B 运行时改写
4. **重建可分析 ELF**：把运行镜像按正确段布局写成 3 段合成 ELF（`artifacts/nesec_runtime_dump/libnesec_full.so`），IDA 自动分析出 **4,226 个函数**（4,012 在解密段，160 静态，54 导入 thunk）。
5. **伪代码**：`artifacts/nesec_full_decomp/`（2,136 份）+ `artifacts/nesec_gui_decomp/`（2,036 份，GUI 批量导出），合计覆盖 **4,172 / 4,173** 个可反编译函数；唯一失败 `0x11c798` 是导入 thunk。`0xf5d08` 构造器已单独特判导出。
6. **函数清单**：`artifacts/nesec_full_decomp/functions.csv`（4,226 行：地址、函数名、大小、区域）。
7. **字符串表**：运行时解密算法已还原（见 §2），解出 3,008 条字符串。
8. **设备侧观测**：Frida 抓到 `NEDialog.showRiskMessage(4,"")`、`getService("user.xposed.system")`、`/system/bin/su` 等访问。

---

## 1. ELF 结构

| 段/节 | 地址 | 大小 | 说明 |
|------|------|------|------|
| `.gnu.fragment` | `0x190` | `0xDBE70` | **加密段**，运行时原地解密，包含真实代码与字符串表 |
| `.text` | `0xf4030` | 16 B | 跳板 |
| `.gnu.draft` | `0xf4040` | `0x117A8` | 加载器/工具函数（静态可读） |
| `.gnu.stub` | `0x109b00` | `0x21E8` | init/fini + 导入跳板 |
| `.data` | `0x10d060` | `0xF738` | 数据/全局表 |
| `.dynsym` / `.dynstr` | `0x10bce8` / `0x10c3f8` | 1,416 / 2,728 B | 导出名被加密成乱码 |
| `.init_array` | `0x109b00` | 4 项 | `0xF5504 / 0xF55B4 / 0xF5D08` 等，做字符串/环境初始化 |
| `.fini_array` | `0x109b20` | 3 项 | 清理 |

依赖：`liblog libz libdl libandroid libc libm libstdc++`。
导入：`dlopen/dlsym/dl_iterate_phdr/dladdr`、`fopen/fgets/sscanf`、`sigaction/raise/mprotect`、`pthread_*`、`getenv` 等。

`JNI_OnLoad` 没有明文导出符号；运行时由 `sub_7C458` 通过名字查找并调用（见 §4.1）。

---

## 2. 字符串加密（已完全还原）

### 2.1 算法

`sub_B1BEC(dst, src)` → 逐字节调用 `sub_D2668`：

```asm
; sub_D2A74: x22 = &key_table (0x1403c), x21 = 0
; sub_D2668:
and  w9, w21, #7
ldr  w9, [x22, w9, uxtw #2]   ; key[i & 7]
eor  w8, w8, w9               ; cipher ^ key
and  w2, w8, #0x7f            ; 只取低 7 位
; 追加到 std::string
```

- 密钥表 `0x1403c` = **`{1,2,3,4,5,6,7,8}`**
- 解密：`plain = (cipher ^ key[i & 7]) & 0x7f`
- 密文可带高位（`|0x80`），解码时被 `&0x7f` 丢弃。
- 每个字符串独立从 `i=0` 开始计相位。

### 2.2 验证

| 密文地址 | 结果 |
|---------|------|
| `0x1c955` | `XposedBridge` |
| `0x1b2ad` | `user.xposed.system` |
| `0xe9260` | `showRiskMessage` |
| `0x1b279` | `getService` |
| `0x19994` | `MyJni` |
| `0x18e38` | `MyApplication` |
| `0x1ab74` | `getEnvInfo` |
| `0x134e5` | `com/netease/nis/wrapper/plugin/InstrumentationProxy` |
| `0x1c962` | `libxposed_art.so` |
| `0x1c97d` | `libsubstrate` |
| `0x1c98a` | `frida-agent-` |
| `0x1c997` | `libriru_` |
| `0x1c9c6` | `code_cache/inject.dex` |

### 2.3 字符串分类（节选，完整见 `artifacts/nesec_runtime_dump/strings_categories.json`）

- **Root**：28 条 su 路径（`/system/bin/su`、`/sbin/su`、`/su/bin/su`、`/apex/.../su`、`/system/bin/.ext/.su`、`/system/xbin/sugote*`、`/system/xbin/supolicy` 等）
- **模拟器/云真机**：81 条（vbox/vbox86/goldfish/qemu、Genymotion、BlueStacks、Nox/bignox、MEmu/microvirt、Droid4X、ttVM、xiaopiVM、androVM、windroyed、ldinit/ldmountsf、XCPlayer、bstshutdown、VMOS、网易 mumu 等）
- **Hook**：`XposedBridge`、`libxposed_art.so`、`libsubstrate`、`frida-agent-`、`libriru_`、`libexp824`、`inject.dex`、`app_process{32,64}_{x,z}posed`
- **调试**：`TracerPid`、`/proc/self/status`、`/proc/%d/task/%d/status`、`/proc/%d/mem`、`/proc/self/fd`、`/proc/self/task`
- **属性**：`ro.kernel.qemu`、`ro.genymotion.version`、`qemu.sf.fake_camera`、`microvirt.*`、`init.svc.{vbox86-setup,noxd,droid4x,ldinit,microvirtd,ttVM_x86-setup}`、`ro.build.*`、`ro.hardware`
- **包名**：BlueStacks/Nox/MEmu/androVM/网易 mumu，以及 `com.samsung.`、`com.miui.`、`com.meizu.`、`com.tencent.` 等 ROM 特征
- **证书**：`tbsCertificate`、`signatureAlgorithm`、`issuer`、`subject`、`subjectPublicKeyInfo`、`certificates-[optional]`、`signatureValue` —— ASN.1/X.509 解析器

---

## 3. 函数总览（4,226 个）

| 区域 | 数量 | 说明 |
|------|------|------|
| `0x190..0xf4000`（解密段） | 4,012 | 检测引擎、C++ 运行时、ASN.1、字符串表辅助 |
| `0xf4000..0x11c798`（静态段） | 160 | 加载器、init/fini、工具函数、thunk |
| `0x11c798+`（导入 thunk） | 54 | `malloc/fopen/...` |

- 完整清单：`artifacts/nesec_full_decomp/functions.csv`
- 伪代码：`artifacts/nesec_full_decomp/functions/<addr>.c`（2,136）+ `artifacts/nesec_gui_decomp/<hex>.c`（2,036）
- 覆盖：4,172 / 4,173；未导出的 `0x11c798` 是导入 thunk，不是独立业务函数。
- 调用图高入度：`sub_DAEB0(286)`、`sub_4B188(247)`、`sub_4E8A8(93)`、`sub_6638C(87)`、`sub_D27D0(87)` —— 均为 `std::`/内存管理运行时，不是检测逻辑。

### 3.1 关键函数（检测/加载）

| 地址 | 大小 | 角色 | 证据 |
|------|------|------|------|
| `sub_7C458` | 0x50 | 按名字找 `JNI_OnLoad` 并调用，置 `byte_EDA25` | 代码 + 字符串 `JNI_OnLoad` |
| `sub_861D8` | 0x288 | `com/netease/nis/wrapper/MyJni` JNI 桥 | 代码 + 字符串 xref |
| `sub_A05AC` | 0xD48 | `MyApplication`/`Utils` 相关大函数（JNI 反射/签名解析） | 代码 + 字符串 xref |
| `sub_A460C` | — | `getEnvInfo` 实现 | 代码 + 字符串 xref |
| `sub_8040C` | — | `InstrumentationProxy` 相关检查/装载 | 代码 + 字符串 xref |
| `sub_9D304` | 0x1A38 | **风险 JNI 句柄缓存**：拼 `NEDialog`/`showRiskMessage` 并缓存 jclass/jmethodID | 代码 + 字符串 xref + 运行时 |
| `sub_9D400` | — | **风险回调执行**：用缓存句柄 `CallStaticVoidMethod`；IDA 未把它列为独立函数（伪代码中显示为 `loc_9D400`） | 反汇编（`0xA3EE8` 调用点） |
| `sub_A3848` | 0x8E0 | **判定执行器**：调风险发射 + `exit` | 代码（唯一调用 `sub_9D304` 与 `sub_D1F4C` 的函数） |
| `sub_D1F4C` | 0xA0 | 退出路径（3 处 `exit_group`） | 代码（raw BL） |
| `sub_2D610` | 0x18 | `syscall(SYS_exit_group=94)` 内联封装 | 代码 |
| `sub_97BDC` | 0x658 | Root：28 条 su 路径 + mount/stat 检查 | 代码 + 字符串 xref |
| `sub_CB5E0` | 0x364 | Magisk：扫描 `/proc/mounts` 的 `magisk`/`system_root` | 代码 + 字符串 xref |
| `sub_8BE38` | 0x2DC | 反调试：遍历 `/proc/<pid>/task/<tid>/status` 找 `TracerPid` | 代码 + 字符串 xref |
| `sub_8FA84` | 0x708 | `/proc/self/fd` + `/proc/self/task` + `/proc/%d/task/%s/status` 扫描 | 代码 + 字符串 xref |
| `sub_8AD50` | 0x2C4 | `/proc/%d/mem`、`/proc/%d/task/%d/mem` | 代码 + 字符串 xref |
| `sub_A3848` | 0x8E0 | `/proc/%d/task/%d/comm` 服务/线程扫描 + 判定执行 | 代码 + 字符串 xref |
| `sub_B39F4` | 0x3B0 | `/proc/self/status` 检查 | 代码 + 字符串 xref |
| `sub_B1C24` | 0xCE4 | 模拟器文件/属性：nox/droid4x/ttVM/xiaopi/windroy/bluestacks/ldinit/androVM | 代码 + 字符串 xref |
| `sub_9D304` | 0x1A38 | 风险发射 + `packageNames`/`com.samsung.` 辅助检查 | 代码 + 字符串 xref |
| `sub_A13EC` | 0x2398 | 代码注入：`DexPathList$Element`、`libdexfile.so` | 代码 + 字符串 xref |
| `sub_AA7B4` | — | Xposed 服务探针：`getService("user.xposed.system")` | 代码 + 字符串 xref + 运行时 |
| `sub_AA61C` | — | 调用 `sub_AA7B4` 的上层 | 代码（raw BL） |
| `sub_6C644` | 0xD8 | Hook 字符串表初始化（Xposed/frida/substrate/riru） | 代码 |
| `sub_FDE30` | 0x2A0 | `/proc/self/maps` 解析器（ELF AArch64 过滤） | 代码 |
| `sub_A706C` / `sub_ADE74` / `sub_B10D4` / `sub_DA560` | — | maps 扫描的 4 个入口 | 代码 + 字符串 xref |
| `sub_FB87C` | 0x12C | `LD_PRELOAD` 解析（最多 9 项） | 代码 |
| `sub_C9724` | 0xBF8 | `getPackagesForUid` 包名检查 | 代码 + 字符串 xref |
| `sub_CA334` | 0x1244 | `VMOS_MANAGER_SERVICE` 检查 | 代码 + 字符串 xref |
| `sub_8D9B8` | 0xA24 | DEX 头/魔数（`dex\n035`）解析 | 代码 + 字符串 xref |
| `sub_8F544` | 0xE8 | `dex2oat`/运行时编译特征 | 代码 + 字符串 xref |
| `sub_CDCC8` | 0x19E8 | X.509/ASN.1 证书解析（签名校验） | 代码 + 字符串 xref |
| `sub_D04D0` | — | `android_log_processLogBuffer` 日志解析 | 代码 + 字符串 xref |
| `sub_92948` / `sub_AE120` | — | `ro.build.version.sdk` 分支 | 代码 + 字符串 xref |

### 3.2 字符串交叉引用（Capstone 全函数扫描）

完整结果：`artifacts/nesec_runtime_dump/string_xrefs.json`。关键项：

```
0x97bdc  <- /bin/su /xbin/su /su/bin/su /data/local/*/su /system/bin/su ...
0xcb5e0  <- magisk, system_root
0x8be38  <- /proc/%d/task/%d/status, TracerPid:
0x8fa84  <- /proc/self/fd, /proc/self/task, /proc/%d/task/%s/status
0x8ad50  <- /proc/%d/mem, /proc/%d/task/%d/mem
0xa3848  <- /proc/%d/task/%d/comm
0xb39f4  <- /proc/self/status
0xb1c24  <- nox/ldinit/ldmountsf/microvirt/droid4x/windroy/bluestacks/ttVM 文件
0xa13ec  <- dalvik/system/DexPathList$Element, libdexfile.so
0xa706c,0xade74,0xb10d4,0xda560 <- /proc/self/maps
0xfb87c  <- LD_PRELOAD
0xc9724  <- getPackagesForUid
0xca334  <- VMOS_MANAGER_SERVICE
0xcdcc8  <- tbsCertificate/issuer/subject/subjectPublicKeyInfo/signatureValue
0x8d9b8  <- dex\n035
0x8f544  <- dex2oat
0xaa7b4  <- getService, user.xposed.system, XposedBridge
0x9d304  <- showRiskMessage, NEDialog
```

---

### 3.3 全量函数分类（4,226）

- 方法：73 个关键函数锚点 + 调用图可达性（前向深度 3 / 反向深度 2）+ 入度 + 特征启发式。
- 置信度：**high 73 / medium 2,000 / low 2,153**。
- 主要分桶：`leaf_util` 1,303、`common_util` 879、`unclassified` 609、`inject_check_support` 146、`cert_asn1_support` 119、`probe_caller_support` 101、`runtime_common` 82、`vmos_check_support` 80、`verdict_support` 79、`risk_emitter_support` 56、`missing` 54。
- 明细文档：`libnesec_函数分类汇总.md`
- CSV：`artifacts/nesec_full_decomp/function_classification.csv`（address/name/size/region/category/confidence/evidence/detail）
- 说明：`*_support` = 从该检测函数可达，不表示专属；`unclassified` = 当前证据不足，不表示无功能。

## 4. 关键功能详解

### 4.1 JNI 入口与 Java 桥

- `sub_7C458(handle)`：`sub_DB400(handle, "JNI_OnLoad")` → 调用 `JNI_OnLoad(vm, 0)`，成功置 `byte_EDA25=1`。
- `sub_861D8`：`com/netease/nis/wrapper/MyJni` 相关（JNI 方法注册/查找）。
- `sub_A05AC`：`MyApplication`/`Utils` 相关大函数，处理字段签名（`(L...;)V` 等）与反射调用。
- `sub_A460C`：`getEnvInfo` 实现。
- `sub_8040C`：引用 `com/netease/nis/wrapper/plugin/InstrumentationProxy`，做 Instrumentation 代理相关处理/检查。
- Java 侧 `MyJni` 的 13 个 native 入口（`load/ra/rp/run/ip/cp/cl/id/iha/d/e/ed/getEnvInfo`）由本库注册；`MyApplication` 另有 276 个混淆 native 方法（162 static + 114 instance），构成 native 功能面。

### 4.2 风险发射与退出（核心链路）

**已定位：`sub_9D304`（0x9D304–0x9ED3C，0x1A38 字节）内部包含风险回调块；`0x9D400` 是它的一个冷块，不是独立函数。**

```asm
; sub_9D304 内部
adrp x21, #0xe9000 ; add x21,#0x260   -> 0xe9260 "showRiskMessage"
adrp x8,  #0xee000 ; ...              -> 缓存 jclass/jmethodID 到 0xeeea8/0xeeeb0
bl   #0x9d2b4                          -> 构造 std::string（解密字符串）
... FindClass("NEDialog") / GetStaticMethodID
```

- `sub_A3848` 先 `sub_B42D4(ctx,...)`、再 `sub_9D304(ctx)`（准备句柄），随后在 `0xA3EE8` 调 `sub_9D400(ctx)` 完成 `CallStaticVoidMethod`；两者都围绕同一个 context 对象。
- `sub_A3848` 在 `0xA3CDC` 依据 context 偏移 `+181` 的标志调用 `sub_D1F4C`（退出）；`+189/+202/+209/+210/+220/+251/+255/+272` 等偏移参与判定/分支。
- 运行时实测：`NEDialog.showRiskMessage(4, "")`，Java 栈只有一帧 → 调用方是 native。
- `sub_A3848` 同时调用 `sub_9FF30(ctx,...)`（→ `sub_AA7B4` Xposed 服务探针）与 `sub_A13EC`（代码注入检查），是检测聚合点。
- `sub_D1F4C` 有三条 `exit_group` 路径（`sub_2D610` → `x8=94; svc #0`）：
  - `exit(1)`、`exit(0)`、`exit(2)`（对应不同失败阶段）。
- 结论：**判定聚合在 `sub_A3848`，JNI 句柄缓存在 `sub_9D304`，风险回调在 `sub_9D400`，退出在 `sub_D1F4C/sub_2D610`。**

### 4.2.1 风险发射的实际入口块与“隐藏副本”澄清

**结论：不存在第二份隐藏的 libnesec 代码副本。** 实际执行的是模块映射内的代码，但入口不是 IDA 定义的函数起点，而是函数内部的**冷块**。

- 风险发射链：`0xAFD70`（`sub_AFB34` 内部块）→ `sub_69E94` → JNI `CallStaticVoidMethodV`（函数表 idx142）。
- `0xAFD78`：`mov w3, w20`（index）；`0xAFD7C`：`mov x4, x24`（message）；`0xAFD80`：`bl sub_69E94`。
- 运行时 JNI idx142 的 `va_list` 解析确认 `index=4`；该调用的返回地址为 `libnesec.so!0xafd84`（模块内），不是 Frida/匿名区。
- **patch `0xAFD70` 或 `0xAFD80` 都能阻止 index 4 的弹出**，证明模块代码就是执行体。
- 之前“模块 entry patch 无效”的原因：壳直接跳转到 `0xAFD70` 这个内部块，而不是 `sub_AFB34` 的 IDA 函数起点 `0xAFB34`；`sub_AFB34` 的入口从未被执行。
- 匿名可执行区核查：`0x74f2281000`（28KB）是 PLT 跳板（`ldr x16; br x16`），不是代码副本；其余匿名区为 ART/JIT/Frida；用 `sub_AFB34` 签名与 `exit_group` 指令扫描均未发现第二份 libnesec 代码。

**布局**：执行基址 = Frida 的 `libnesec.so` 模块基址（每次启动 ASLR 不同）；关键块偏移固定为 `0xAFD70`（风险发射）、`0x2D610`（exit_group 存根）、`0xAFB34`（IDA 函数起点，实际未作为入口）。壳的块级入口说明其控制流做了块拆分/重排，静态函数边界不等于运行时入口。

### 4.2.2 exit(255) 的通道（ptrace 实测）

用 NDK 编译的 arm64 ptrace 工具 attach 全部线程，捕获最终退出 syscall：

```
libnesec base=0x71ef380000
EXIT tid=21664 nr=94 status=4294967295 pc=0x71ef3ad614 off=0x2d614
     map=.../lib/arm64/libnesec.so
  stack[66] 0x71ef42f784 (off=0xaf784, libnesec)
```

- 退出就是 `libnesec.so!0x2D610` 的内联存根：`mov x8,#0x5e; svc #0`，`x0 = -1`（无符号 0xFFFFFFFF）→ 退出码 255。
- 调用链包含 `+0xAF784`（`sub_AFB34` 的块区），说明退出不一定经过 `sub_D1F4C`；`sub_2D610` 也可被该块直接调用。
- **patch `+0x2D610` 为 `ret` 后，进程不再干净退出，而是 SIGSEGV**：退出被阻止，但代码在“本应终止”的路径上继续执行并崩溃。
- 只有一份 libnesec 文本映射（`/proc/pid/maps` 仅一个 offset=0 的 r-xp 段），不存在第二份代码副本。

**退出调用序列（0xAF7CC）**：

```asm
0af7cc: bl   #0xb45cc
0af7d0: adrp x8, #0xe9000
0af7d4: ldr  x3, [x8, #0x210]   ; x3 = *(0xEE210)，退出调度器（模块加载时为 0，运行时初始化）
0af7d8: adrp x1, #0x2d000
0af7dc: add  x1, x1, #0x610     ; x1 = 0x2D610（exit_group 存根）
0af7e0: mov  w0, #-1            ; status = -1 → 退出码 255
0af7e4: mov  w2, #0xa
0af7e8: ldr  x30, [sp], #0x10
0af7ec: br   x3                 ; 间接调用调度器 → 执行 x1 存根
```

**干净绕过**：把 `0xAF7EC` 的 `br x3` patch 为 `ret`（`c0 03 5f d6`），退出调用被跳过，进程持续存活（实测 pid 存活 >12s；仅出现 index 4，后续检测流水线不再继续）。这比重 patch 退出存根（导致 SIGSEGV）更安全。

**稳定性验证（2026-11-21）**：
- 注入 patch 后进程存活 35s+，Frida detach 后仍存活（pid 13174）。
- 截图确认 UI 正常：启动页 → 点击“跳过” → 首页列表与底部 Tab 正常渲染。
- logcat 无 FATAL/ANR；仅有正常 SDK/网络日志与一次 Toast（index 4）。
- 复跑脚本：`artifacts/frida/sampleb_exit_bypass.js`。


### 4.3 Root

`sub_97BDC`：

- 构造 28 条路径（`/system/bin/su`、`/su/bin/su`、`/apex/com.android.art/bin/su`、`/system/bin/.ext/.su`、`/system/xbin/sugote*`、`/system/xbin/supolicy`、`/odm/bin/su`、`/vendor/xbin/su`、`/dev/su` 等）。
- 对每条做 `access/stat` 类检查；同时读取 mount/文件状态。
- 返回布尔；命中对应文案 index 5（`检测到设备已Root`）。

`sub_CB5E0`：

- 读 `/proc/mounts`（按行迭代）。
- 匹配 `magisk`、`/sbin/%[^/]/block/%n`、`/dev/%[^/]/%[^/]/block/%n`，以及 `system_root ` / `system `。
- 置全局 `byte_EDA88`；返回布尔。

### 4.4 反调试

`sub_8BE38`：

- `getpid()` → `sub_D89C4` 取任务列表。
- 遍历 `/proc/<pid>/task/<tid>/status`，`fopen/fgets` 逐行：
  - 命中 `TracerPid:` → 解析数值；非 0 且不是自身 → 风险。
  - 命中 `State:` 且后续含 `(zombie)` → 风险。
  - 命中两次即判定。
- 相关：`sub_8FA84` 扫 `/proc/self/fd`（readlink 每个 fd，找注入的 mem/fd）、`/proc/self/task`、`/proc/%d/task/%s/status`；`sub_8AD50` 访问 `/proc/%d/mem`、`/proc/%d/task/%d/mem`；`sub_A3848` 扫 `/proc/%d/task/%d/comm`；`sub_B39F4` 检查 `/proc/self/status`。
- **`sub_B39F4` 细节（IDA GUI 伪代码）**：读取 `/proc/self/status`，若 `Seccomp:` 值为 2 且伴随标志为 1 → 置风险串；随后检查 `NativeBridgeError` / `libnativebridge.so`、`linker64`、`__dl___loader_dlopen`，并解密 `.lebiansdk` / `lbmust.odex` 两个串做进一步校验，命中置 `byte_EA9C4=1`。

### 4.5 模拟器/云真机

`sub_B1C24`（IDA GUI 伪代码，完整 568 行）构造三组表：

- **文件/路径（约 80 条）**：`/system/bin/ldinit`、`/system/bin/ldmountsf`、`/system/lib/libldutils.so`、`/system/bin/microvirt-prop`、`/system/lib/libdroid4x.so`、`/system/bin/windroyed`、`/system/bin/nox-prop`、`/system/lib/libnoxspeedup.so`、`/data/property/persist.nox.simulator_version`、`/data/misc/profiles/ref/com.bignox.app.store.hd`、`/system/bin/ttVM-prop`、`/system/bin/droid4x-prop`、`/data/.bluestacks.prop`、`/system/etc/xxzs_prop.sh`、`/system/etc/mumu-configs/device-prop-configs/mumu.config`、`/data/bluestacks.prop`、`/dev/nemuguest`、`/data/data/com.bluestacks.*`、`/data/data/com.microvirt.*`、`/data/data/com.mumu.*`、`/data/data/com.netease.mumu.cloner`、`/system/bin/bstshutdown`、`/sys/module/bstinput`、`/sys/bus/pci/drivers/bstaudio`、`/sys/class/misc/bst_gps`、`/system/app/bluestacksHome.apk`、`/system/phoenixos`、`/xbin/phoenix_compat`、`/init.dundi.rc`、`/system/etc/init.dundi.sh`、`/init.andy.cloud.rc`、`/system/bin/xiaopiVM-prop`、`/system/bin/XCPlayer-prop`、`/system/lib/liblybox_prop.so`、`/data/youwave_id`、`/dev/vboxguest`、`/sys/*/vbox*`、`/system/bin/androVM-*`、`/system/etc/init.androVM.sh`、`/system/lib/vbox*.ko`、`/dev/goldfish_pipe`、`/sys/module/goldfish_*`、`/sys/module/kvm*`、`/init.android_x86_64.rc`、`/init.androidVM_x86.rc`、`/init.intel.rc`、`/init.vbox2345_x86.rc` 等。
- **属性（约 20 条）**：`init.svc.microvirtd`、`bst.version`、`ro.phoenix.version.code/build`、`ro.phoenix.os.branch`、`init.svc.droid4x`、`microvirt.memu_version/imsi/mut`、`init.svc.su_kpbs_daemon`、`init.svc.noxd`、`init.svc.ttVM_x86-setup`、`init.svc.xxkmsg`、`ro.build.remixos.version`、`init.svc.ldinit`、`ro.genymotion.version`、`init.svc.pkVM_x86-setup`、`ro.andy.version`。
- **包名**：`com.bluestacks.gamepophome/s2p/BstCommandProcessor/bstfolder` 等。
- 判定：路径用 `sub_D7F4C`（存在性）、属性用 `sub_AE120`（取值匹配）；命中即置结果 1。
- 关联：`sub_9D304` 还引用 `packageNames`、`com.samsung.`；`sub_CA334` 检查 `VMOS_MANAGER_SERVICE`。

### 4.6 Hook / Xposed / 注入

- `sub_6C644`：把加密字符串解密到 `0xeeed8` 起始的结构体数组，条目含 `XposedBridge`、`libxposed_art.so`、`libexp824`、`libsubstrate`、`frida-agent-`、`libriru_`、`/data/local/`、`libhello.so`、`unportect.so`、`code_cache/inject.dex`、`me/weishu/exposed/ExposedBridge`；随后注册回调 `sub_6C71C`。
- `sub_AA7B4`：引用 `getService`、`user.xposed.system`、`XposedBridge`；通过 JNI 调 `ServiceManager.getService("user.xposed.system")`。运行时已观测到该调用与 `avc: denied { find }`。
- `sub_AA61C`：`sub_AA7B4` 的调用方。
- `sub_A13EC`：引用 `dalvik/system/DexPathList$Element`、`libdexfile.so`，对应 dex 注入/类加载链检查。
- 既往动态证据：运行时解密段 `libnesec+0x93714` 调 `FindClass(com/swift/sandhook/SandHook)`、`FindClass(org/lsposed/lspatch/.../LSPAppComponentFactoryStub)`；`libnesec+0xb2830` 调 `FindClass(me/weishu/exposed/ExposedBridge)`。

### 4.7 maps / LD_PRELOAD

- `sub_FDE30`：`fopen("/proc/self/maps")` + `fgets`，`sscanf("%lx-%lx %4s %lx %*x:%*x %*d%n")`；筛选权限首字符 `r` 且 ELF `e_machine==0xB7`（AArch64）的模块，交给回调匹配路径。
- `sub_A706C / sub_ADE74 / sub_B10D4 / sub_DA560`：另外 4 个 maps 入口（不同用途：模块枚举、注入检测、环境校验）。
- `sub_FB87C`：`getenv("LD_PRELOAD")`，按空格拆最多 9 项，逐个比较。

### 4.8 完整性 / 签名 / DEX

- `sub_CDCC8`：X.509/ASN.1 解析器（`tbsCertificate`、`signatureAlgorithm`、`issuer`、`subject`、`subjectPublicKeyInfo`、`extensions`、`attestation`），由 `sub_A4CDC` 在证书判定路径调用；失败发射风险 index 5。详见专篇 `libnesec_证书校验分析.md`。
- 证书来源：`sub_A4CDC` 通过 JNI 反射类 `android/support/v4/os/ks/bc` 的静态方法 `ga/v/gn/go` 获取/比较证书字节。类名**确实内嵌在 libnesec**：vaddr `0x1E4A2`，30 字节密文，用本文 §5.2 的 XOR 密钥解出；`sub_D8B48` 在 `0xA4E70` 解码到栈上。
- **该类在本构建不存在**：APK 全部 zip 条目、4 个 .so、解密镜像明文、13 个运行时 dex（含 t=60s 二次转储）均无该类；3 个 ClassLoader 的 `loadClass` 全部 `ClassNotFoundException`。镜像内也无 `CAFEBABE`（不走 DefineClass）。
- 因此 `sub_A4CDC → sub_CDCC8` 这条证书链在本构建**不可达**：`sub_A4CDC` 启动时确被 ART 回调执行 1 次（块级下桩），但开关 `+0x101` 当时为 0，在 `0xA4E60` 直接返回；`sub_CDCC8` 从未进入，`sub_A460C` 全部块 0 命中。
- 证据倾向**无密码学验签**：镜像中无 SHA/MD5 轮常量、无 RSA/ECDSA OID、无 libcrypto；更可能是证书字段/字节 pinning（`v(byte[],byte[])`）。
- `sub_8D9B8`：DEX 魔数 `dex\n035` 解析（dex 完整性/格式检查）。
- `sub_8F544`：`dex2oat` 特征（运行时编译/OTA 环境）。
- `sub_7C458`：`JNI_OnLoad` 存在性与调用。

### 4.8.1 混淆结构（OLLVM 排查结论）

- **无 OLLVM 平坦化 / MBA**：全库 3,664 个函数 `BR`=0，547 个仅 1 个 `BR`（尾调用/thunk）；伪代码里的 `ORR/TST/CSEL` 是 libc++ 短字符串优化，`SDIV+ADD/SUB` 是 `%3` 强度削减。
- 唯一异常区 `0xBD698..0xC3B98` 是 **256 项 opcode 表、228 个 handler 的线索化解释器**（分派表 `0x17084`，目标 `0xBD914 + u16*4`）；入口 `0xBD698` 由 `sub_A89B4` 在遍历 JNI 签名时调用，输入是极短类型描述符（实测 `""`、`"L"`），收尾按 `'['`/`'L'` 处理 JNI 返回类型。结论：JNI 参数/返回编组器，不是保护业务逻辑的 VMP。
- 已重建 229 个 handler 函数边界、导出 195 份伪代码与 opcode 映射。详见专篇 `libnesec_OLLVM与VM还原.md`，产物 `artifacts/nesec_vm/`。
- **检测执行面实测**（块级下桩）：冷启动真正执行的检测函数 72 个；风险 4/6/8 实测发射（Frida/Hook/注入/Xposed）；`sub_A3848`/`sub_A460C` 全部块 0 命中；证书开关 `+0x101` 在 A4CDC 调用时为 0。详见 `libnesec_标志位与检测实测.md`。

### 4.9 包名 / 服务 / 日志

- `sub_C9724`：`getPackagesForUid` 包名枚举。
- `sub_CA334`：`VMOS_MANAGER_SERVICE`（VMOS 云手机）。
- `sub_9D304`：`packageNames`、`com.samsung.` 等 ROM/包名辅助判定。
- `sub_D04D0`：`android_log_processLogBuffer`（日志解析）。
- `sub_92948` / `sub_AE120`：`ro.build.version.sdk` 分支（不同 Android 版本策略）。

---

## 5. 21 类风险与 native 功能映射

`NEDialog.f1a` 的 21 个下标（0–20），以及目前能对上的 native 函数：

| i | 风险 | native 证据/候选 | 状态 |
|---|------|------------------|------|
| 0 | 来源未授权 | `sub_CDCC8`（X.509）、`sub_8D9B8`（dex） | 部分 |
| 1 | 应用被篡改 | `sub_9D304` → `sub_D39D8(w2=1)`（`[x19+0xb3]`）；`sub_CDCC8`/`sub_8D9B8` | **已定位发射点** |
| 2 | 调试器 | `sub_8BE38` → `AFB34(w1=2)`；`sub_8AAAC` → `AFB34(w1=2)`；`sub_9D304` → `D7FA4(w1=2)` | **已定位** |
| 3 | 模拟器 | `sub_B1C24`；`sub_9D304` @0x9db8c `csel w1,3,0` | **已定位** |
| 4 | Hook 框架 | `sub_90250`/`sub_91338`/`sub_A3848` → `AFB34(w1=4)`；`sub_9D304` @0x9db64 | **已定位** |
| 5 | Root | `sub_97B88` → `AFB34(w1=5)`；`sub_A4CDC`/`sub_CC4A0` → `AFB34(w1=5)`；`sub_9D304` | **已定位** |
| 6 | 异常注入 | `sub_A13EC`；`sub_B39F4` → `D55AC(w2=6)` | **已定位** |
| 7 | 代理 | `sub_96E58` @0x971c8 → `AFB34(w1=7)`（`sub_833FC` 判定分支） | **已定位** |
| 8 | Xposed | `sub_9D304` @0x9def0 → `D39D8(w2=8)`（`[x19+0xbe]`）；`sub_AA7B4` | **已定位** |
| 9 | 试用版 | Java `NEDialog.showProbation` | **已定位（Java）** |
| 10 | VPN | `sub_96E58` @0x97980 → `AFB34(w1=10)` | **已定位** |
| 11 | 双开 | `sub_9D304` @0x9df6c → `D60A4(w2=11)`（`[x19+0xcc]`） | **已定位** |
| 12 | USB 调试 | `sub_9D304` @0x9e0c0 → `D7FA4(w1=12)`（`sub_7E5A4` 判定） | **已定位** |
| 13 | ROM 异常 | `sub_9D304` @0x9ed00 → `D85E4(w2=13)`；`sub_92948` | **已定位发射点** |
| 14 | 模拟点击 | `sub_9D304` @0x9ec04 → `D7FA4(w1=14)`（`sp+0x140` 值 3/4） | **已定位** |
| 15 | 云手机 | `sub_9D304` @0x9eca4 → `D39D8(w2=15)`（`[x19+0xf9]`）；`sub_CA334` | **已定位** |
| 16 | 虚拟机 | `sub_9D304` @0x9df90 → `D60A4(w2=16)`（`[x19+0xf8]`）；`sub_B1C24` | **已定位** |
| 17 | 屏幕共享 | **本构建无可达发射点**（见 §5.1） | **未接线** |
| 18 | 异常服务 | `sub_A3848`（`/proc/.../comm`）、`sub_C9724`；具体发射点未定 | 部分 |
| 19 | 虚拟定位 | `sub_A413C` @0xa43ec → `AFB34(w1=19)`；`sub_9D304` @0x9ec78 → `D7FA4(w1=19)`（`[x19+0xf7]`） | **已定位** |
| 20 | 抓包工具 | `sub_9D304` @0x9ecbc → `D85E4(w2=20)`（`[x19+0xfe]`） | **已定位** |

> 发射器链路：`sub_AFB34(env, index)` 使用 `sub_9D304` 缓存的 jmethodID（`qword_EE0A8/EE0B0`）；`sub_D7FA4` 是它的尾调用别名；`sub_D39D8/sub_D55AC/sub_D60A4/sub_D85E4` 是工作项包装（w2=index）。实际执行入口块与“隐藏副本”澄清见 §4.2.1。

### 5.1 关于 index 17（屏幕共享）的结论

`NEDialog.f1a[17]` 的文案存在（“检测到屏幕共享,请关闭相关工具后重试”），但本构建中**没有任何可达的发射点**：

- 全部 18 个 `sub_AFB34/sub_D7FA4` 发射调用点中，常量只有 1/2/3/4/5/6/7/8/10/11/12/13/14/15/16/19/20 与动态 index；没有 17。
- 全镜像扫描没有任何 `mov w1,#0x11` / `mov w2,#0x11`（唯一 0x11 是 `sub_AA7B4` 的字符串长度参数）。
- 对 libnesec 做 7-bit 掩码加密字符串搜索（8 个相位）：`MediaProjection/VirtualDisplay/DisplayManager/screen/projection/capture` 均无命中；`cast/mirror` 只命中 C++ RTTI 片段 `mirror::Class`。
- libsecsdk.so / libInno.so / libapp.so 中无屏幕共享检测代码或中文文案。
- 2.0s 晚窗口内存 dump 与首次 dump 的差分为数据/重定位改写，未出现新的 17 常量。
- 运行期：index 4 先于其他检测退出；开启 `screenrecord` 后 hook JNI 发射器仍未观察到 17。

**结论**：17 是该加固版本的通用文案槽位，但本 APK 没有接线对应的屏幕共享检测；因此无法“对上”到具体函数（不是我们没找到，而是不存在可达调用）。

---

## 6. 等价还原代码

代码目录：`artifacts/libnesec_equiv/`

| 文件 | 等价对象 | 说明 |
|------|----------|------|
| `yidun_string.c/.h` | `sub_B1BEC` + 字符串表 | 实现 `plain=(cipher^key[i&7])&0x7f`，内置已恢复表 |
| `yidun_root.c` | `sub_97BDC` / `sub_CB5E0` | 28 条 su 路径 + `/proc/mounts` magisk 检查 |
| `yidun_debug.c` | `sub_8BE38` / `sub_B39F4` / `sub_8FA84` | TracerPid、/proc/self/status、fd/task 扫描 |
| `yidun_emulator.c` | `sub_B1C24` / `sub_CA334` | 文件/属性/包名（nox/vbox/goldfish/microvirt/VMOS…） |
| `yidun_hook.c` | `sub_6C644` / `sub_AA7B4` | maps 扫描 Xposed/frida/substrate/riru + 服务探针 |
| `yidun_maps.c` | `sub_FDE30` | `/proc/self/maps` 解析（AArch64 ELF 过滤） |
| `yidun_ldpreload.c` | `sub_FB87C` | `LD_PRELOAD` 拆分比较 |
| `yidun_package.c` | `sub_C9724` / `sub_9D304` | 包名/ROM 特征 |
| `yidun_exit.c` | `sub_2D610` / `sub_D1F4C` | `exit_group` 等价封装 |
| `yidun_engine.c/.h` | `sub_A3848` | 汇总检查并返回 21 类风险 index |
| `main.c` | — | 命令行演示：打印命中的风险项 |
| `Makefile` | — | 本机可编译（Linux/macOS；Android 上 `__system_property_get` 可用） |

**边界**：等价代码实现的是“可观察行为”，不包含易盾的混淆、反调试对抗、加密段布局；`sub_9D304` 的 JNI 风险弹窗在纯 native 代码里以 `yidun_report()` 回调代替。

**已验证**：`make` 通过（macOS/Clang，`-Wall -Wextra` 无警告）；`./yidun_equiv --decode d9f2ecf7e0e2c5fae8e6e4e1` 输出 `XposedBridge`，与 §2.2 一致。

---

## 7. 未知与限制

1. **反编译覆盖已补齐**：4,173 个可反编译函数中 4,172 个已导出（`nesec_full_decomp` 2,136 + `nesec_gui_decomp` 2,036）；唯一失败 `0x11c798` 是导入 thunk。`0xf5d08`（init 构造器）已单独导出。
2. **风险 17（屏幕共享）**：本构建未接线。18 个发射调用点无 17 常量，libnesec/libsecsdk/libInno/libapp 均无屏幕共享检测代码或字符串，晚窗口 dump 也无新增 17 常量（详见 §5.1）。
3. **“隐藏副本”已澄清（否定）**：不存在第二份 libnesec 代码；实际执行的是模块内冷块（如 `0xAFD70`），运行时入口 ≠ IDA 函数起点。详见 §4.2.1。
4. **退出通道已定位**：`libnesec.so!0x2D610` 的内联 `svc exit_group`，`x0=-1`（退出码 255），syscall PC = base+0x2D614；调用链包含 `+0xAF784`。patch 该存根后进程转 SIGSEGV（退出被阻止但继续执行崩溃）。详见 §4.2.2。
5. **`sub_A3848`** 的 context 结构与各标志（`+181/+189/+202/+209/+210/+220/+251/+255/+272` 等）含义未完整还原（该函数未被 OLLVM/VM 处理，是普通分支代码，见 §4.8.1）。
6. **证书校验策略（已定性为死代码）**：`sub_CDCC8/sub_CF6B0` 的 ASN.1 解析已确认；但类 `android/support/v4/os/ks/bc`（方法 `ga/v/gn/go`）在本构建的 APK、全部 .so、13 个运行时 dex、3 个 ClassLoader 中均不存在，`sub_A4CDC` 冷启动 70s 零命中，`sub_CDCC8` 的唯一调用者又是 `sub_A4CDC` → 整条证书链不可达。期望值表 `qword_1EA48/qword_1EC28` 的格式未还原。详见 `libnesec_证书校验分析.md`。
7. **服务端**：native 本地判定已确认（断网仍退出）；是否存在服务端二次风控仍未证明。
8. **字符串表**：已解出 3,008 条；仍有部分表项是二进制/嵌套密文，未逐条分类。

---

## 8. 复现步骤

```sh
# 1) 运行时 dump（需 root frida-server）
python3 /tmp/wm_tools/dump_nesec.py
# 产物：artifacts/nesec_runtime_dump/nesec_late_*.bin + libnesec_late_flat.bin

# 2) 重建可分析 ELF
python3 /tmp/wm_tools/mkelf.py
# 产物：artifacts/nesec_runtime_dump/libnesec_full.so

# 3) 伪代码（REA/IDA）
#    decompile_all -> artifacts/nesec_full_decomp/
#    GUI 批量导出（推荐，绕过 headless 门禁）：
#      IDA 打开 libnesec_full.so -> File -> Script file -> export_pseudocode.py
#      -> artifacts/nesec_gui_decomp/

# 4) 等价代码
cd artifacts/libnesec_equiv && make && ./yidun_equiv
```

---

## 附录 A：产物索引

| 路径 | 内容 |
|------|------|
| `artifacts/nesec_runtime_dump/libnesec_late_flat.bin` | 运行时内存镜像（1,167,360 B） |
| `artifacts/nesec_runtime_dump/libnesec_full.so` | 合成可分析 ELF |
| `artifacts/nesec_runtime_dump/strings_categories.json` | 分类字符串 |
| `artifacts/nesec_runtime_dump/string_xrefs.json` | Capstone 字符串交叉引用 |
| `artifacts/nesec_full_decomp/functions.csv` | 4,226 函数清单 |
| `artifacts/nesec_full_decomp/functions/` | 2,136 份伪代码 |
| `artifacts/nesec_gui_decomp/` | 2,036 份 GUI 批量导出的伪代码（含全部关键失败函数） |
| `artifacts/libnesec_equiv/` | 等价 C 代码 |

## 附录 B：关键哈希

| 文件 | SHA-256 |
|------|---------|
| libnesec.so（原始） | `8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff` |
| libnesec_full.so（合成） | `8c5b8f3cc044118f2875b0a07e46fedc0cc8381990e73139b475320948a066c2` |
| libnesec_late_flat.bin | 见 `shasum artifacts/nesec_runtime_dump/libnesec_late_flat.bin` |
