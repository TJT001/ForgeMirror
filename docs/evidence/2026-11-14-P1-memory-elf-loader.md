# 2026-11-14 P1：内存 ELF loader 与 safejni

## 范围

把选定的业务 `.so` 从 APK 的明文 `lib/` 移除，加密为
`assets/shield/native/<abi>/<name>.enc`；`ShieldClassLoader.findLibrary` 解密到
匿名 memfd，通过 `android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` 加载，不把
明文 ELF 持久化到磁盘。

同时新增 `safejni.h`：JNIEnv 局部引用、UTF/byte array、方法查找和异常清理的
RAII 封装，供 native loader 使用。

## 实现

| 位置 | 内容 |
|---|---|
| `protect.py` | `--in-memory-libs libfoo.so,...`；HKDF `FM/native/v1` + AES-GCM（`FMN1`）加密选定业务库，写 assets 并从 APK 删除原 `lib/` 条目 |
| `ShieldNativeLoader.java` | 按 ABI 读取加密 asset、派生 native key、解密、调用 `ShieldRuntime.nativeLoadInMemory`；从调用栈识别业务类并注册隐式 `Java_*` native 方法 |
| `native_loader.cpp` | `nativeLoadInMemory`：memfd 写入 → `android_dlopen_ext`；`nativeRegister`：按短符号 `dlsym` + `RegisterNatives` |
| `safejni.h` | `LocalRef`、`Utf8String`、`ByteArray`、`findClass/staticMethod/method/toString`、异常清理 |
| `ShieldClassLoader.findLibrary` | 优先使用加密 asset 的内存加载；不存在时回退 APK `lib/` |
| `app_native_caller` | 识别 `/memfd:` caller，使 memfd 加载的业务库仍进入透明 I/O hook |
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
ShieldNativeLoader: loaded from memfd libdemo.so
ShieldNativeLoader: loaded from memfd libdemo2.so
ShieldNativeIo: open shadow fd=... merge_probe.txt
readback prefs=true counter=1 file=true append=true ra=true
         mmap=true sqlite=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
dupErr=0 javaDup=D2XYZ6 second=7 lockErr=0
merge writeErr=0 closeErr=0 main=MAIN remote=REMOTE
files/harness_ra_renamed.txt magic: 46 4d 46 32 (FMF2)
```

无 `UnsatisfiedLinkError`，原生探针和透明 I/O 均正常；v2rayNG 默认保护回归
`bootstrap ok state=4`。

测试：Shield JVM 39 项、Python pipeline 66 项、Go 测试通过。

## 限制

1. 使用 Android linker 从 memfd 加载，不是 libDexHelper 的自研 `elf__load`
   重定位/符号解析器；没有实现独立 ELF 映射和自定义 relocation。
2. 隐式 `Java_*` 注册使用短符号，重载 native 方法需要补长符号/签名的精确
   mangling；`JNI_OnLoad` 若依赖业务 ClassLoader/FindClass，可能因 linker
   调用上下文而失败。
3. 占位路径按库名生成唯一 `libshield_holder_<hash>.so`；双库连续加载已在
   demo 验证（`second=7`），但占位 ELF 的 SONAME 仍相同，极端 linker 行为需继续观察。
4. 只处理显式选择的库；依赖库、`dlopen` 直连路径、x86 原生 hook 未覆盖。
5. `safejni` 目前是 header-only 基础层，尚未覆盖全部 JNI 引用类型和异常语义。
