# 2026-11-13 P1：自解密 shell core

## 范围

把 `libshield_core.so` 从 APK 明文原生库改为按 ABI 加密的 asset；运行时用
`k_content + build_id` 派生密钥解密到 memfd，由 `libshield_boot.so` 通过
`android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` 加载。

## 实现

| 模块 | 内容 |
|---|---|
| `protect.py` | 每 ABI 读取 `libshield_core.so`，用 `HKDF(k_content, build_id, "FM/core/v1")` + AES-GCM 加密为 `assets/shield/core/<abi>.enc`；从 APK 丢弃明文 core；config 写 `core=shield/core` |
| `ShieldCoreLoader.java` | 按 64/32 位与 `SUPPORTED_ABIS` 选择 asset；`FMC1` 信封（magic+nonce+ciphertext+tag）解密；写入 `memfd` |
| `ShieldRuntime.java` | 取得 `k_content` 后加载 core，把 memfd fd 传给 `nativeBootstrapWithCore`；关闭 pfd |
| `boot.cpp` | `load_core_fd` 用 `android_dlopen_ext` 从 fd 加载 core；`fm_boot_with_core_fd` / JNI `nativeBootstrapWithCore` |
| `protect.py` CLI | `--self-decrypt-core/--no-self-decrypt-core`；关闭时保留明文 core 回退 |

## 验证

APK 检查：

```text
assets/shield/core/arm64-v8a.enc
assets/shield/core/armeabi-v7a.enc
assets/shield/core/x86.enc
assets/shield/core/x86_64.enc
无 lib/*/libshield_core.so
config: "core": "shield/core"
```

设备（Pixel 5 / API 30）：

```text
ShieldRuntime: encrypted core opened fd=59
ShieldRuntime: bootstrap ok state=4
ShieldRuntime: rule scan done matches=4 ms=254
```

- `protect` 的 S8 gate 仍 `passed: true`；
- 明文 core 不在 APK，静态提取只能拿到 AES-GCM 密文；
- 关闭选项时走原明文 `libshield_core.so` 加载路径（兼容回退）。

## 限制

1. 只加密 core；`libshield_boot.so`、`libshield_hook.so`、`libshield_yara.so` 仍为明文。
2. boot 自身不加密，密钥由 Java 在授权/本地 key 后派生；进程内仍可取到明文 core。
3. 未实现双 `PT_DYNAMIC` 诱饵、DT_INIT 自解密、LZSS、I-cache 刷新、内联 syscall 桩。
4. memfd core 在 `/proc/self/fd` 可见；无自定义 ELF loader。
5. x86/x86_64 core 可解密加载，但原生 hook 仍仅 ARM。
