# 2026-11-13 P1：第三方 APK 加固兼容（v2rayNG 2.4.0）

## 范围

用 `v2rayNG_2.4.0_arm64-v8a.apk` 验证真实第三方应用加固，修复三个阻断点：

1. S0 因 `minSdkVersion=24` 直接拒绝；
2. 启动后 `ShieldIntegrity` 报 `signing certificate mismatch`，进入恢复页；
3. MMKV 在 `files/mmkv/` 下打开/映射文件被 hook 以 `EACCES` 拒绝。

## 修复

| 问题 | 修复 |
|---|---|
| `minSdkVersion=24` | 壳的内存 DEX 加载需要 API 26；S0 改为 `W_MIN_SDK_RAISED` 警告，S6 在 manifest 中把 `uses-sdk:minSdkVersion` 抬到 26（只升不降），并写保护 warning |
| 签名证书 pin 错 | 原实现 pin 的是**输入 APK** 证书，但 HSM 模式最终用 `~/.android/debug.keystore` 重签；改为从 debug keystore 读取 SHA-256 并 pin 最终签名证书。`customer_local` 不 pin，给 `W_CERT_UNPINNED`；读不到 keystore 给 `W_CERT_FALLBACK`；签名后若仍不一致给 `W_SIGNER_MISMATCH` |
| 非策略文件被拒绝 | `ShieldNativeIo.open` 用 `-2` 表示“路径不在加密策略内”，native hook 遇到 `-2` 放行到原 libc；只有真正受保护但解密失败才 `EACCES`。`rename/unlink/truncate/ftruncate/mmap` 也改为按策略判断，而非只要位于 `files/` 就拒绝 |

相关实现：

- `formats/axml.py`：`set_int_attr`、`raise_min_sdk`（缺失 `uses-sdk` 时插入）；
- `tools.py`：`debug_signer_sha256`（keytool 读取 debug keystore）；
- `intake.py`：低 minSdk 从拒绝改为警告；
- `ShieldNativeIo.java`：`protectedPath` JNI 判定；
- `file_hooks.cpp`：`java_is_protected`、`-2` 放行、策略感知的 rename/unlink/truncate。

## 验证

### v2rayNG

```text
minSdkVersion: 26（原 24）
versionCode: 4000760
原始 Application: com.v2ray.ang.AngApplication
```

设备（Pixel 5 / API 30）：

```text
FMDecrypt: lzss ok=1 / hash=... / stub done（boot、hook、yara）
ShieldRuntime: dex loaded count=5 decryptMs=2341 pssKb=143945
ShieldRuntime: encrypted core opened fd=50
ShieldRuntime: bootstrap ok state=4
ShieldApplication: attachBaseContext state=4
ShieldApplication: original Application attached: com.v2ray.ang.AngApplication
ShieldApplication: original Application onCreate
ShieldRuntime: activity context adapted: com.v2ray.ang.ui.main.MainActivity
MMKV: open fd[0x32] /data/user/0/com.v2ray.ang/files/mmkv/SETTING
MMKV: mmap ... [SETTING]；SETTING/SUB/MAIN 读写正常
```

主界面正常显示“配置项 / 未连接”，无恢复页、无 MMKV `Permission denied`。

### demo 回归

```text
ShieldNativeIo: open shadow fd=67 .../files/harness_ra_renamed.txt
readback prefs=true counter=1 file=true append=true ra=true mmap=true
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
textErr=0 native=T2XYZ6 java=T2XYZ6 mmapWriteErr=0
javaMmap=M2XYZ6 periodic=P2XYZ6
```

受保护 `.txt` 仍走 memfd 快照与回写，未被“放行非策略文件”削弱。

### 测试

Python 65 项测试通过，新增：

- `raise_min_sdk` 升版、幂等、缺失 `uses-sdk` 插入；
- 低 minSdk 的 intake 结果从 `E_MIN_SDK` 改为 `W_MIN_SDK_RAISED` 且 `ok=true`。

## 限制

1. `minSdkVersion` 被抬到 26，原应用将无法安装到 API 24/25 设备；这是壳内存 DEX 加载的硬约束。
2. `customer_local` 不绑定签名证书，需由客户自行保证签名一致性。
3. `debug_signer_sha256` 依赖 `keytool`；缺失时回退 pin 输入证书并告警（第三方应用会在启动时签名校验失败）。
4. v2rayNG 的 VPN 实际连接未在本次验证中启用，只验证了加固壳、原生库和 MMKV 存储链路。
