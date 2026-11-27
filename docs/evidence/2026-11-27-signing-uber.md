# 2026-11-27：uber-apk-signer 签名接入

## 范围

为加固产物增加 `--signing-mode uber`：使用外部 uber-apk-signer 对已对齐的 APK 签名，解决 `customer_local` 只对齐、不产签名包的问题。`customer_local` 仍保留为“输出未签名包由客户签名”的模式。

## 实现

| 位置 | 内容 |
|---|---|
| `backend/pipeline/forgemirror/intake.py` | `SIGNING_MODES` 增加 `uber` |
| `backend/pipeline/forgemirror/tools.py` | `sign_uber()`：调用外部 JAR，带 `--skipZipAlign`、`--allowResign`；`keystore_sha256()` 读取自定义 keystore 证书 |
| `backend/pipeline/forgemirror/protect.py` | `ProtectOptions` 增加 JAR/keystore 参数；`uber` 模式在 `zipalign -P 16` 后签名，并用签名证书填充 manifest `cert_sha256` |
| `backend/pipeline/forgemirror/cli.py` | `--signing-mode uber`、`--uber-apk-signer`、`--keystore`、`--ks-alias`、`--ks-pass`、`--key-pass` |
| `backend/tests/pipeline/test_signing.py` | 签名模式注册、缺少 JAR、缺少 keystore 密码的负例 |
| `docs/components.lock.json` | 登记 uber-apk-signer 1.3.0（Apache-2.0，外部 JAR，不随仓库分发） |

关键行为：

- 先执行 SDK 的 `zipalign -P 16`，uber 调用带 `--skipZipAlign`，避免把 16 KB 对齐改回 4 字节。
- `--allowResign` 清除输入 APK 残留的旧 `META-INF` 签名。
- 未提供 `--keystore` 时使用 `~/.android/debug.keystore`；提供自定义 keystore 时必须给 `--ks-pass`，`--key-pass` 默认复用 storepass。
- `customer_local` 不签名；`hsm` 仍走本地 apksigner + debug keystore。

## 工具

| 项 | 值 |
|---|---|
| 版本 | 1.3.0 |
| JAR | `uber-apk-signer-1.3.0.jar` |
| SHA-256 | `e1299fd6fcf4da527dd53735b56127e8ea922a321128123b9c32d619bba1d835` |
| 校验 | 与 Release 页 `checksum-sha256.txt` 一致 |
| 许可 | Apache-2.0 |
| 分发 | 不 vendoring；由使用者提供 JAR 路径 |

## 构建与验证

```bash
python3 -m forgemirror protect \
  --apk android/app/build/outputs/apk/debug/app-debug.apk \
  --out artifacts/uber-sign \
  --signing-mode uber \
  --uber-apk-signer /tmp/uber-apk-signer-1.3.0.jar \
  --key-file artifacts/pkr1-remote/keys/k_content.bin \
  --build-id 11111111-2222-4333-8444-555555555555
```

`protected.protect.json`：

```text
ok=true signed=true signing_mode=uber
signer_sha256=3050b4521ad2c7fcb14b386cddd22acb122b2d60a1d8f325e29afc80ae525170
package=dev.forgemirror.demo version_code=1
```

签名与对齐：

```text
apksigner verify --print-certs -v
  v1 (JAR signing): false
  v2: true
  v3: true
  Signer #1: CN=Android Debug, SHA-256 3050b452…5170

zipalign -c -P 16 -v 4
  Verification successful
```

v1=false 是预期：minSdk 26，v2/v3 已覆盖目标系统；未开启 v4。

设备侧（Pixel 5 在测试期间 USB 断开，改用 API 37 模拟器）：

```text
adb install -r artifacts/uber-sign/protected.apk
  Success

ShieldRuntime: native container open ms=560
ShieldRuntime: dex loaded count=8 decryptMs=994
ShieldRuntime: bootstrap ok state=4
ShieldDetect: yidun signatures source=pkr1 ...
ShieldDetect: finding env_emulator ...
ShieldDetect: finding yidun_emulator property:ro.kernel.qemu=1
ShieldDetect: finding yidun_usb_debug Settings.Global.ADB_ENABLED=1
```

## 限制

1. JAR 不随仓库分发；生产前需固定版本、校验和应用供应链审查。
2. 默认 debug keystore 只适合开发/研究；正式发布必须使用 release keystore 或 HSM 流程，不要沿用 `CN=Android Debug`。
3. `--ks-pass`/`--key-pass` 会出现在命令行进程参数中；敏感环境应使用受控终端并注意 shell 历史。
4. `--allowResign` 会移除输入 APK 已有签名；不得用于客户已签名交付包的二次签名。
5. 签名必须位于 `zipalign -P 16` 之后，且 uber 必须 `--skipZipAlign`；调整顺序会破坏签名或 16 KB 对齐。
6. v1 未生成；minSdk 26 下 v2/v3 足够。如后续支持更低 minSdk，需要重新评估。
