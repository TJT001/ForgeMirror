# 2026-11-21 P2：白盒化内容密钥（native）

## 范围

内嵌的 32 字节 `K_content` 不再以明文写入 APK。构建期用 Chow 白盒 AES 表
把内容密钥包成 `WBK1`，并在保护时把白盒表导出为紧凑的 `WBX1` 二进制；运行时
在 `libshield_boot.so` 内完成解包、HKDF 派生和 FDX2 容器解密。Java 线程
拿不到根密钥，只拿到按用途派生的密钥和明文 DEX。

## 实现

| 位置 | 内容 |
|---|---|
| `backend/tools/whitebox/java/com/risid/wbaes` | Chow 白盒 AES-128 运行时（BSD-3），仅构建期使用，不再进入 App DEX |
| `formats/data/wbaes.table` | 白盒表原始 Java 序列化数据，仅作为构建输入 |
| `formats/whitebox.py` | `export_table()` 生成 `WBX1` 扁平表；`wrap()` 生成 `WBK1` 包裹块；均调用同一套构建期 Java 工具 |
| `cpp/vault/fm_whitebox.c` | 解析 `WBX1`，按 T1/T2/T3、XOR 级联与 XORState 级联还原白盒 AES，生成 CTR keystream 并解包 `WBK1` |
| `cpp/vault/fm_aes.c` / `fm_sha256.c` | 自带 AES-256-GCM、SHA-256、HMAC-SHA256、HKDF；容器 TOC/分块解密与逐文件摘要校验 |
| `cpp/vault/fm_vault.c` | 安装根密钥、按标签派生 policy/file/native/rules/core key、解析 FDX2 |
| `cpp/vault_jni.cpp` + `ShieldKeyVault.java` | JNI 边界：白盒解包、派生、容器解密 |
| `ShieldRuntime` | 读 `k_content.wb` 后调用 native 安装；policy/rules/core 改为接收派生密钥；DEX 由 native 返回 |
| API / worker / 前端 | `whitebox` 选项透传；界面“白盒密钥库”开关默认开启 |

### 数据格式

```text
WBK1 | nonce(12) | ciphertext(32)        # 内容密钥包裹块
WBX1 | version | t1/t2/t3/xor/xorstate   # 扁平白盒表，1,196,064 字节
```

### 密钥边界

```text
assets/shield/k_content.wb ──┐
assets/shield/wbaes.table  ──┼─> libshield_boot: 解包 -> K_content（仅 native）
                              │        ├─ HKDF("FM/policy/v1") -> Java policy
                              │        ├─ HKDF("FM/files/v1")  -> Java 文件层
                              │        ├─ HKDF("FM/native/v1") -> Java native 层
                              │        ├─ HKDF("FM/rules/v1")  -> Java rules
                              │        └─ HKDF("FM/core/v1")   -> Java core
                              └─> FDX2 解密 -> 明文 DEX 交给 ART
```

`K_content` 只在 native 全局缓冲区中存在；容器、policy（SPK1）、rules
（PKR1）与 core（FMC1）的信封解密全部在 native 内完成，policy/rules/core
的派生密钥不再进入 Java。Java 仅持有文件层与 native 层两把派生密钥。
完整性由 GCM tag、逐文件 SHA-256 与 TOC 边界检查共同保证。

## 验证

- 构建产物：
  ```text
  assets/shield/k_content.wb       48 B
  assets/shield/wbaes.table        1,196,064 B (WBX1)
  无 assets/shield/k_content.bin、无 assets/wbaes.table
  ```
- 主机向量（`backend/tests/vectors/vault`）：白盒解包、5 个 HKDF 标签、
  12.7 MB 多分块容器、空文件、篡改容器/密钥均通过。
- Pixel 5 / API 30：
  ```text
  ShieldRuntime: content key unwrapped in native white-box vault ms=4
  ShieldRuntime: native container open ms=359
  ShieldRuntime: dex loaded count=8 decryptMs=656
  ShieldRuntime: bootstrap ok state=4 metrics bootstrapMs=773
  MainActivity: probe ... native=T2XYZ6 java=T2XYZ6 dependency=7 dlopen=7 lockErr=0
  ```
- 主进程与 `:remote` 进程均走 native 解包；S8 gate 全部通过。

## 限制

1. 白盒表随 APK 分发，拿到表即可离线解出 `WBK1`。已改为**每构建随机生成**
   （Chow 生成器 + 随机 16 字节表密钥，冷启动约 16 s、热生成约 0.5 s；
   `--no-whitebox-random-table` 回退随包固定表），跨构建不再共享同一张表，
   公开固定表的哈希/特征检测也随之失效。生成器构建期依赖 BouncyCastle
   `bcprov-jdk15on` 1.61（Maven Central 拉取，sha256 固定校验），只进构建
   工具、不进 App。它隐藏的是根密钥的明文存储，不是完整的白盒 AES-GCM；
   运行时仍会在 native 内存短暂持有 `K_content`。
2. native 代码可被 Frida/native hook 或内存 dump 分析；相比 Java 层显著抬高门槛，
   但不是绝对防护。后续可接表随机化、表加密与 `mlock`。
3. 构建期需要 JDK（`javac`/`java`），用于白盒包裹和 `WBX1` 导出；无 JDK 时
   白盒选项失败，不会退回明文。
4. debug 变体 NDK 默认 `-O0`，`shield_boot` 显式加 `-O2`；否则纯 C 实现在
   设备上会慢约 40 倍。
5. 文件层（FMF1、chunk store、随机访问、SharedPreferences）仍在 Java 用
   fileKey 解密；该密钥由文件栈常驻使用，下沉需重构整条 I/O 链路。
