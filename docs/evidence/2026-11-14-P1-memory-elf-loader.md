# 2026-11-14 P1：内存 ELF loader 与 safejni

## 范围

把选定的业务 `.so` 从 APK 的明文 `lib/` 移除，加密为
`assets/shield/native/<abi>/<name>.enc`；`ShieldClassLoader.findLibrary` 解密后交给
自研 ELF loader：直接解析 program header、映射 PT_LOAD、应用 RELA/REL/RELR、
解析动态符号、执行 INIT/INIT_ARRAY。平台 linker 仅作为不支持的 ELF/失败时的
fallback。

同时新增 `safejni.h`：JNIEnv 局部引用、UTF/byte array、方法查找和异常清理的
RAII 封装，供 native loader 使用。

## 实现

| 位置 | 内容 |
|---|---|
| `protect.py` | `--in-memory-libs libfoo.so,...`；HKDF `FM/native/v1` + AES-GCM（`FMN1`）加密选定业务库，写 assets 并从 APK 删除原 `lib/` 条目 |
| `ShieldNativeLoader.java` | 按 ABI 读取加密 asset、解析 `DT_NEEDED`、递归预加载加密依赖（`RTLD_GLOBAL`）、调用 `ShieldRuntime.nativeLoadInMemory`；从调用栈识别业务类并注册隐式 `Java_*` native 方法；带 `JNI_OnLoad` 的库回退临时文件以保留 ClassLoader 上下文 |
| `elf_loader.cpp` | 自研 ELF64/ELF32 loader：PT_LOAD 映射、RELA/REL/RELR、`DT_PLTREL` 选择 PLT REL/RELA、符号表/GNU hash、INIT/INIT_ARRAY、`R_*_RELATIVE/ABS/GLOB_DAT/JUMP_SLOT/IRELATIVE/COPY`、`PT_GNU_RELRO` 只读、cache flush、镜像地址注册 |
| 符号解析失败 | 未定义且非 weak 的符号解析失败时 loader 返回 `nullptr`，回退平台 `memfd + android_dlopen_ext`，不再把 0 写进 GOT 后崩溃 |
| 依赖兜底 | `DT_NEEDED` 依赖没有加密 asset 时用 `System.loadLibrary` 预加载明文依赖；依赖由自研 loader 加载时调用其 `JNI_OnLoad` |
| `native_loader.cpp` | `nativeLoadInMemory` 优先调用自研 loader，失败回退 memfd + `android_dlopen_ext`；`nativeRegister` 对自定义 handle 使用自研符号解析，否则 `dlsym` |
| `fm_elf_contains_address` | 导出自定义镜像地址范围，供 native hook 判断 caller 是否业务代码 |
| `safejni.h` | `LocalRef`、`Utf8String`、`ByteArray`、`findClass/staticMethod/method/toString`、异常清理 |
| `ShieldClassLoader.findLibrary` | 优先使用加密 asset 的内存加载；不存在时回退 APK `lib/` |
| `app_native_caller` | 识别 `/memfd:` caller 和自研 loader 的镜像地址，使业务库仍进入透明 I/O hook |
| `dlopen` hook | 原生 `dlopen("libfoo.so")` 命中加密 asset 时，解密到临时缓存文件并调用原 `dlopen`，避免在 hook 内重入 linker |
| `libshield_dummy.so` | 作为模板；每个加密库生成唯一 `libshield_holder_<hash>.so` 占位路径，供 ClassLoader 登记 |

### 加载链

```text
MainActivity.<clinit> System.loadLibrary("demo")
  → ShieldClassLoader.findLibrary("demo")
      → 读取 assets/shield/native/<abi>/libdemo.so.enc
      → HKDF(k_content, build_id, "FM/native/v1") + AES-GCM 解密
      → nativeLoadInMemory：memfd → android_dlopen_ext
      → 从栈找到 MainActivity，dlsym Java_* → RegisterNatives
      → 返回 libshield_dummy.so（APK 内占位路径）
  → Runtime.nativeLoad 登记占位库
  → nativeProbe* 调用已注册的内存库函数
```

## 验证

APK 结构（`--in-memory-libs libdemo.so`）：

```text
assets/shield/native/arm64-v8a/libdemo.so.enc
assets/shield/native/armeabi-v7a/libdemo.so.enc
assets/shield/native/x86/libdemo.so.enc
assets/shield/native/x86_64/libdemo.so.enc
lib/<abi>/libshield_holder_<sha256(libname)[:16]>.so
无 lib/*/libdemo.so
```

设备（Pixel 5 / API 30）：

```text
FMElf: loaded libdemo2.so base=... size=20480
DemoSecond: JNI_OnLoad from demo2
ShieldNativeLoader: JNI_OnLoad libdemo2.so returned 65542
FMElf: loaded libdemo.so base=... size=438272
ShieldNativeLoader: loaded from memfd libdemo.so
ShieldNativeIo: open shadow fd=... merge_probe.txt
readback prefs=true counter=1 file=true append=true ra=true
         mmap=true sqlite=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
dupErr=0 javaDup=D2XYZ6 dependency=7 dlopen=7 overload=11/12 lockErr=0
merge writeErr=0 closeErr=0 main=MAIN remote=REMOTE
harness_ra_renamed.txt magic: 46 4d 46 32 (FMF2)
files/harness_ra_renamed.txt magic: 46 4d 46 32 (FMF2)
```

无 `UnsatisfiedLinkError`，原生探针和透明 I/O 均正常；`libdemo` 的加密依赖
`libdemo2` 通过 `DT_NEEDED` 预加载，`dependency=7`；重载 native 方法短/长符号
均注册成功（`overload=11/12`）。v2rayNG 默认保护回归 `bootstrap ok state=4`。

ARM32（Pixel 5 / API 30，`adb install --abi armeabi-v7a` 强制 32 位安装）：

```text
ShieldHook: hook __loader_dlopen at 0xec5967d1 ok
FMElf: loaded libdemo2.so base=0xe7fed000 size=8192
FMElf: loaded libdemo.so base=0xb6d1f000 size=249856
ShieldHook: dlopen redirect libdemo2.so
MainActivity: probe ... dependency=7 dlopen=7 lockErr=0 overload=11/12
```

API 37（Android 16 / arm64 模拟器）同样验证了自研 loader：`libdemo2`、
`libdemo` 均由 `FMElf` 加载，`dependency=7 dlopen=7 overload=11/12` 全通过。
hook/ClassLoader 的 API 37 适配见 `2026-11-14-P1-api37-hooks.md`。

测试：Shield JVM 39 项、Python pipeline 68 项、Go 测试通过。

## 限制

1. 自研 loader 已覆盖 ELF64 ET_DYN 的 PT_LOAD、RELA/REL/RELR、`DT_PLTREL`、
   动态符号/GNU hash、INIT/INIT_ARRAY、RELRO、RELATIVE/ABS/GLOB_DAT/JUMP_SLOT/
   IRELATIVE/COPY；仍不支持 TLS relocation，其余未识别类型按失败处理并回退平台 linker。
2. ELF32 路径已在 Pixel 5 / API 30 的 `armeabi-v7a` 安装上验证：`FMElf` 加载
   libdemo2/libdemo，探针 `dependency=7 dlopen=7 lockErr=0 overload=11/12` 全通过；
   x86/x86_64 尚未真机验证。
3. 带 `JNI_OnLoad` 的主库回退到 cache 临时文件加载，保证 ClassLoader 上下文；
   文件在 10 秒后删除、启动时清理，存在短暂明文窗口。重载方法已按长符号注册。
   自研 loader 加载的依赖库会调用其 `JNI_OnLoad`（demo2 返回 65542 已验证）。
4. 占位路径按库名生成唯一 `libshield_holder_<hash>.so`；双库、JNI_OnLoad
   回退均已在 demo 验证；占位 ELF 的 SONAME 仍相同，极端 linker 行为需继续观察。
5. 已处理显式 `System.loadLibrary`、加密 `DT_NEEDED` 依赖和 `dlopen` 直连
   名称；未加密依赖走 `System.loadLibrary` 兜底；`dlopen` 使用临时文件避免
   linker 重入，存在短暂明文窗口；x86 原生 hook 仍未覆盖。
6. 部分加密场景（只加密 `libdemo.so`、`libdemo2` 留在 `lib/`）下，自研 loader
   解析不到跨自定义镜像/平台镜像的符号时按失败回退平台 loader，探针
   `dependency=7` 正常，但该路径不再由自研 loader 承载。
7. `safejni` 目前是 header-only 基础层，尚未覆盖全部 JNI 引用类型和异常语义。
