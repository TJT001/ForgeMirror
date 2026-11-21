# 2026-11-21 P2：白盒化内容密钥

## 范围

给内嵌的 32 字节 `K_content` 增加白盒包裹层：构建期不再写
`assets/shield/k_content.bin` 明文，而是写 `k_content.wb`（CTR 包裹块）和
Chow 白盒 AES 表；运行时只在解包阶段恢复内容密钥，再进入现有 HKDF/AES-GCM 链路。

## 实现

| 位置 | 内容 |
|---|---|
| `com.risid.wbaes` | 引入 ph4r05/Risid 的 Chow 白盒 AES-128 运行时（BSD-3），保留版权头与 LICENSE |
| `formats/data/wbaes.table` | 白盒 AES 表（Java 序列化），只作为构建期输入；保护时注入 `assets/shield/wbaes.table` |
| `formats/whitebox.py` | 构建期编译 `WhiteboxKeyTool`，用白盒表对 nonce/counter 生成 CTR keystream，包裹 `K_content` |
| `protect.py --whitebox-key` | 写 `assets/shield/k_content.wb`、`assets/shield/wbaes.table`；config 的 `key` 指向 `.wb`；不支持时失败/告警 |
| `ShieldWhitebox.java` | 从 assets 反序列化表（仅允许 `com.risid.wbaes.*`）、生成 keystream、解包并校验 `WBK1` 布局 |
| `ShieldRuntime` | 读到 `WBK1` 时先解包，再派生 file/native/core key |
| API / worker / 前端 | `whitebox` 选项透传；界面“白盒密钥库”开关默认开启 |

### 包裹格式

```text
WBK1 | nonce(12) | ciphertext(32)
keystream = WBAES_Encrypt(table, nonce || counter_be32) 逐块
ciphertext = K_content XOR keystream
```

构建期 Python 不保存白盒 AES 密钥；它只调用白盒表完成加密。运行时也不需要
`K_content` 以外的白盒密钥。

## 验证

- `protect --whitebox-key` 产物（APK 内只有注入后的两份资产，无根级重复表）：
  ```text
  assets/shield/k_content.wb       48 B
  assets/shield/wbaes.table        1.7 MB
  config.key = shield/k_content.wb
  无 assets/shield/k_content.bin、无 assets/wbaes.table
  ```
- Pixel 5 / API 30 安装运行（主进程与 `:remote` 进程均验证）：
  ```text
  ShieldRuntime: content key unwrapped from white-box vault
  ShieldRuntime: dex loaded count=9 decryptMs=453 adapter=art-29+
  ShieldRuntime: bootstrap ok state=4 metrics bootstrapMs=559
  MainActivity: probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0 textErr=0
    native=T2XYZ6 java=T2XYZ6 dependency=7 dlopen=7 lockErr=0 overload=11/12
  ```
- S8 gate 通过；白盒表与包裹块均纳入签名清单/产物校验。stub DEX 因白盒运行时
  增至约 220 KB，`a2_no_plaintext_dex` 的 stub 上限相应调整到 320 KB，仍远低于
  正常业务 DEX。

## 限制

1. 当前使用固定开源白盒表，表本身会随 APK 分发；它隐藏的是 `K_content` 的
   明文存储，不是完整的“所有 AES 操作白盒化”。运行时仍会在进程内短暂恢复
   `K_content` 供 HKDF 和 AES-GCM 使用。
2. 表为 Java 序列化格式，运行时依赖 `com.risid.wbaes` 类名，已加 consumer
   ProGuard keep；反序列化只接受 `com.risid.wbaes.*` 与基本类型数组。表只存在于
   后端构建数据和保护后的 `assets/shield/`，不再随 shield AAR 进入普通 APK。
3. 构建期需要 JDK（`JAVA_HOME/bin/javac` 和 `java`）；无 JDK 时白盒选项失败，
   不会静默退回明文。
4. 每构建表目前相同，尚未做按构建随机生成白盒表；后续可接生成器做表多样化。
5. 表约 1.7 MB，会增加 APK/AAR 体积；CTR 包裹只保护嵌入密钥，不替代清单签名、
   GCM 认证和授权链路。
