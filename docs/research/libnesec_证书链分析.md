> **来源**：`/Users/taylee/SourceCode/pentest/waimai/libnesec_证书校验分析.md`。
> 证据级别映射：观测→V，代码→S，推断→I，未知→U。产物 `artifacts/...` 相对 `/Users/taylee/SourceCode/pentest/waimai/`，不入本仓库。
> 结论：本构建该链不可达，仅作完整性设计反例；不进入实现（见 `docs/设计文档.md` §17.9）。

---

# libnesec.so 证书校验分析（cert_asn1_support 簇）

- 日期：2026-11-21（2026-11-21 修订：类名来源与可达性定性）
- 范围：`cert_asn1_support` 簇 119 个函数（CSV：`artifacts/nesec_full_decomp/function_classification.csv`）
- 核心：`sub_CDCC8`（0x19E8，ASN.1/X.509 解析）、`sub_CF6B0`（0xDDC，字段提取/比对）、`sub_A4CDC`（0x688，证书判定入口）

---

## 0. 结论摘要

| 问题 | 结论 | 证据 |
|------|------|------|
| 类名 `android/support/v4/os/ks/bc` 从哪来 | **内嵌在 libnesec，XOR 加密**，vaddr `0x1E4A2`，运行时由 `sub_D8B48` 解码 | 密文 `e0ec...` 用 §2 密钥解出完整类名；见 §2 |
| 这个类在哪 | **本构建根本不存在** | APK 全部 zip 条目、4 个 .so、解密镜像、13 个运行时 dex、3 个 ClassLoader 全部未命中；见 §3 |
| 证书链会执行吗 | **不会**。`sub_A4CDC` 启动时确被 ART 回调执行 1 次，但执行时开关 `+0x101 = 0`，在 `0xA4E60` 直接返回；`sub_CDCC8` 从未进入 | 块级 Frida 计数 + 开关实测，见 §4 |
| 是否验签 | 无密码学验签证据；设计是“解析 ASN.1 + 调 Java 助手做字节/字段比对” | 无 SHA/RSA OID/libcrypto；见 §6 |
| 对加固效果的影响 | 证书 pinning 分支在本包是**死代码**，不构成实际检测项 | 上述合取 |

---

## 1. 调用链与门控

```
sub_A5364  (JNI 注册入口；a1=env)
  └─ sub_A413C
       └─ sub_A460C            ← 0xA4500 调用；受 dword_EEAC8 / 配置结构位控制
            └─ sub_A4CDC       ← 0xA48B8 / 0xA48C0 调用
                 ├─ sub_D8B48  解码类名（0xA4E70）
                 ├─ 解析 jclass 并缓存 qword_EE108
                 ├─ GetStaticMethodID ×4 → qword_EE110/EE118/EE120/EE128
                 └─ sub_CDCC8(env, cert_bytes)   ← 0xA4F88
                      ├─ 调 Java 助手（qword_EE108/EE118/EE120/EE128）
                      └─ sub_CF6B0（0xCF6AC）
```

xrefs（IDA，静态确认）：

- `sub_CDCC8` 的调用者**只有** `sub_A4CDC`（0xA4F88）。
- `sub_A4CDC` 的调用者只有 `sub_A460C`（0xA48B8/0xA48C0）。
- `sub_A460C` 的调用者只有 `sub_A413C`（0xA4500）。
- `sub_A413C` 只有自环 + `sub_A5364`（0xA5380）；`sub_A5364` 无代码 xref → 通过 JNI `RegisterNatives` 间接进入。
- `sub_CF6B0` 另有一个调用者 `sub_9D304`（0x9EC9C），属于环境/判定大函数，复用了 ASN.1 字段提取，与证书判定链独立。

门控字段（`sub_A4CDC` 读 `x21` 指向的配置结构）：`+0xD8`、`+0xE0`、`+0xED`、`+0x101`，外加全局 `byte_EDA50` 初始化标志、`dword_EEAC8` 位。任一不满足即整段跳过。

---

## 2. 类名的真实来源（已定位）

`sub_A4CDC` 在 `0xA4E68` 取 `X8 = 0x1E0F0 + 0x3B2 = 0x1E4A2`，`0xA4E70` 调 `sub_D8B48` 解码，`0xA4E74..0xA4E80` 把结果（28 字节 + 终止）写入栈 `x0 = SP+0x140`，随后 `sub_803D0` 构造 `std::string`。

vaddr `0x1E4A2` 原密文：

```
e0 ec e7 f6 ea ef e3 a7 f2 f7 f3 f4 ea f4 f3 a7 f7 b6 ac eb f6 a9 ec fb ae e0 e0 84 ...
```

用 §5.2 的密钥 `{1,2,3,4,5,6,7,8}`、`plain=(cipher^key[i&7])&0x7F` 解码：

```
android/support/v4/os/ks/bc\0
```

即**类名确实是硬编码内嵌**，不是运行时拼接、也不是来自 Java 侧。之前文档写“属运行时加载”是推断过度，这里修正：名字内嵌、类本体缺失。

字符串表邻域（同一密文块，vaddr 递增）还解出证书助手相关常量：

| vaddr | 内容 |
|-------|------|
| 0x1E0F0 | `getEncoded` |
| 0x1E100 | `getSubjectX500Principal` |
| 0x1E118 | `()Ljavax/security/auth/x500/X500Principal;` |
| 0x1E450 | `(Ljava/lang/String;)Ljava/lang/Object;` |
| 0x1E480 | `java/lang/reflect/Proxy` |
| **0x1E4A2** | **`android/support/v4/os/ks/bc`** |
| 0x1E4E8 | `()Landroid/content/pm/PackageManager;` |

---

## 3. 类本体不存在的六项证据

1. **APK zip 全量扫描**：`waimai_base.apk` 全部条目（含 82MB `classes.dex`、`assets/*.jar`）grep `os/ks/bc` = 0 命中。
2. **全部 .so**：`libnesec.so`、`libsecsdk.so`、`libnesec-x86.so`、`libInno.so` 明文均无该串；`libnesec` 的密文形态只出现在 §2 的表项（即“期望类名”，不是类定义）。
3. **解密镜像明文**：`libnesec_late_flat.bin` / `libnesec_full.so` grep `ks/bc`、`bc;`、`/bc` 均为 -1。
4. **镜像无 class 文件**：全镜像 `CA FE BA BE` 出现 0 次 → 不走 JNI `DefineClass` 自造类。
5. **运行时 dex**：t≈5s 与 t≈60s 两次转储 `BaseDexClassLoader.pathList.dexElements`（13 个元素，11 个 in-memory，去重 13 个文件，见 `artifacts/nesec_runtime_dex/MANIFEST.md`），全部无该类；t=60s 未出现任何新 dex。含 50KB/56KB 的易盾 antihijack 插件 dex（`com.netease.antihijack.*`）也没有。
6. **直接 loadClass**：Frida 对 3 个 ClassLoader 依次 `loadClass("android.support.v4.os.ks.bc")`，全部 `ClassNotFoundException`。

> 注：转储脚本证据在 `/tmp/wm_tools/dump_cookie.js`、`dump_late2.js`、`loadclass_test.js`；导出件在 `artifacts/nesec_runtime_dex/`。

---

## 4. 运行时探针结果（2026-11-21 修正）

> 修正说明：先前用“函数入口”下桩得出“零命中”，是错误方法。易盾会跳到函数内部冷块执行（本库普遍现象），入口桩会漏。改用**块级**下桩后结果如下。

`/tmp/wm_tools/blk_probe.js`：对 `sub_A4CDC` 的 17 个内部块 + `sub_A413C/sub_A460C/sub_A3848/sub_9D304` 的块级下桩，冷启动 18s：

| 目标 | 命中 |
|---|---|
| `sub_A4CDC` 入口 `0xA4CDC` | **1 次** |
| `0xA4E60`（读 `+0x101` 的块） | **1 次** |
| `0xA4FB8`（函数尾返回） | **1 次** |
| `0xA4E70`（类名解码 `sub_D8B48`） | **0** |
| `0xA4E9C`（jclass 解析） | **0** |
| `sub_CDCC8` | **0** |
| `sub_A460C` 全部 5 块 | **0** |
| `sub_A3848` 全部 18 块 | **0** |

调用来源：`sub_A4CDC` 的返回地址 `lr = 0x14dc330`，**不在 libnesec 模块内**（模块大小 0x11D000），说明它是被 ART/JNI 注册的回调指针直接调用，不经过 `sub_A460C`。

### 4.1 开关实测（`0xA4E60` 处读 `X21`）

结构指针 `0x733ba28ff8`（全局单例，见 `libnesec_标志位与检测实测.md`）：

| 偏移 | 实测 | 含义 |
|---|---|---|
| `+0xD8` | 1 | 跳过 `sub_83428/sub_D73FC` 分支 |
| `+0xE0` | 1 | 进入 `sub_D88DC` 检查 |
| `+0xED` | 0 | 跳过证书前置块 |
| **`+0x101`** | **0** | `0xA4E60: LDRB W8,[X21,#0x101]; CBZ W8, 0xA4FB8` → **直接返回** |

即：证书检查在启动早期被调用一次，此时开关尚未置位（8s 后同一结构的 `+0x101` 变为 1，但不再有调用）。这是**时序门控错过**，与“类不存在”叠加，使证书链双重不可达。

---

## 5. 期望的 Java 助手契约（从 native 侧反推）

`sub_A4CDC` 的 JNI 序列（`0xA4EBC..0xA4F58`）：

```
cls = FindClass("android/support/v4/os/ks/bc")        // qword_EE108
mid1 = GetStaticMethodID(cls, "ga", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I")  // qword_EE110
mid2 = GetStaticMethodID(cls, "v",  "([B[B)I")                                                     // qword_EE118
mid3 = GetStaticMethodID(cls, "gn", "()[B")                                                        // qword_EE120
mid4 = GetStaticMethodID(cls, "go", "()[B")                                                        // qword_EE128
```

`sub_CDCC8`（ASN.1 主函数）同时引用 `qword_EE108/EE118/EE120/EE128`，说明真正的取值/比对发生在解析过程中：

- `gn()/go(): byte[]` —— 返回两组字节（命名上对应 cert 与 publicKey，或“当前/期望”两份）。
- `v(byte[],byte[]): int` —— 字节比对（很可能返回 0=不一致 / 非 0=一致）。
- `ga(String,String,String,boolean): int` —— 三段字符串 + 开关的判定，可能对应 (证书链, 主机名, pin, 严格模式)。

`sub_A4CDC` 失败时（`0xA4F90`）调 `sub_AFB34(w1=5)`，即风险 index 5。

---

## 6. 是否做密码学验签？——证据仍偏向“没有”

- 镜像无 SHA-1/SHA-256/MD5 轮常量（`0x428a2f98`、`0x5A827999`、`0x67452301`）。
- 无 RSA/ECDSA OID（`1.2.840.113549.1.1.1`、`1.2.840.10045.2.1`、`sha256WithRSAEncryption`）。
- 无 `libcrypto` 依赖、无 `BN_*`/`EVP_*` 字符串、无大数模幂循环。
- ASN.1 侧只做结构解析与字段提取，比对交给 Java 助手（`v`）。

---

## 7. ASN.1 / X.509 解析能力（保留）

`sub_CDCC8/sub_CF6B0` 引用的明文字段名：

```
tbsCertificate, version, serialNumber, signature, issuer, validity, subject,
subjectPublicKeyInfo, issuerUniqueID-[optional], subjectUniqueID-[optional],
extensions-[optional], signatureValue, signatureAlgorithm, certificates-[optional],
attestation, signerInfos, signerInfo, digestAlgorithmId, digestEncryptionAlgorithmId,
encryptedDigest, authenticatedAttributes-[optional], unauthenticatedAttributes-[optional],
contentInfo, issuerAndSerialNumber, crls-[optional]
```

即同时覆盖 X.509 与 PKCS#7/CMS 结构，并识别 `attestation` 扩展。

内嵌表：`qword_1EA48`（0x1EA48，约 400B）、`qword_1EC28`（0x1EC28，1KB+）、`byte_1EBB9`、`qword_13B88`；内容非明文，未匹配 DER `30 82`，格式未还原。

---

## 8. 若要真正 dump 到该类，需要什么

本构建无法 dump，因为对象从未存在。可选路径（按可行性）：

1. **换样本**：同一易盾版本、Java 层带证书助手类的包（同类名固定内嵌，换壳不换名）。
2. **服务端下发**：`com/netease/nis/wrapper/plugin/*` 插件机制（`InstrumentationProxy` + `IlIl` 字样）若从服务端拉取带该类的 dex，加载瞬间 hook `InMemoryDexClassLoader` 即可截获。
3. **逆向等价实现**：按 §5 契约自行实现，语义可由 `sub_CDCC8` 的调用点反推（已有等价工程 `artifacts/libnesec_equiv/`）。

---

## 9. 关键地址

| 地址 | 名称 | 角色 |
|------|------|------|
| 0xa5364 | sub_A5364 | JNI 注册入口 → 0xA413C |
| 0xa413c | sub_A413C | 上层调度 |
| 0xa460c | sub_A460C | 门控 + 调用证书判定 |
| 0xa4cdc | sub_A4CDC | 类解析 + 方法解析 + 触发 ASN.1 |
| 0xa4e70 | — | 类名解码调用点（X8=0x1E4A2） |
| 0xa4f88 | — | 调 sub_CDCC8 |
| 0xa4f90 | — | 失败 → 风险 index 5 |
| 0x1e4a2 | — | 类名密文（30B） |
| 0xcdcc8 | sub_CDCC8 | ASN.1/X.509 主解析 |
| 0xcf6b0 | sub_CF6B0 | 字段提取（被 0xCDCC8 与 0x9D304 复用） |
| 0xd8b48 | sub_D8B48 | 字符串解码器 |
| 0xd80dc | sub_D80DC | GetStaticMethodID 包装 |
