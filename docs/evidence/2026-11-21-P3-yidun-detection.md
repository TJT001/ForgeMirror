# 2026-11-21 P3：吸收易盾 libnesec 检测能力

## 范围

把网易易盾 `libnesec.so` 逆向成果中的**检测能力**吸收进 shield，作为参照样本 B；不复刻其响应方式、字符串混淆和不可达证书链。规格边界见 `docs/设计文档.md` §17.9。

## 研究来源（外部证据，非本项目实测）

| 项 | 值 |
|---|---|
| 样本 | `libnesec.so`（SONAME `libsecexe.so`） |
| SHA-256 | `8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff` |
| 运行时 | 易盾 `7.6.3_996`；`com.waimaiii.waimaiii` 1.1.217 |
| 主文档 | `docs/research/libnesec_易盾加固还原.md` |
| 分报告 | `libnesec_检测实测.md`、`libnesec_证书链分析.md`、`libnesec_VM还原.md`、`libnesec_函数分类.md` |
| 原始产物 | `/Users/taylee/SourceCode/pentest/waimai/artifacts/`（不入本仓库） |

证据级别已按设计文档 §17.1 映射：原文 `观测`→`V`、`代码`→`S`、`推断`→`I`、`未知`→`U`。

## 实现

| 文件 | 内容 |
|---|---|
| `android/shield/src/main/assets/yidun-signatures.json` | 28 条 su 路径、mount 标记、逐线程调试标记、9 条 hook maps 标记、类/服务、fd/LD_PRELOAD 标记、54 条模拟器路径、22 条模拟器属性、云手机包名前缀与 VMOS 服务、标准 DEX 魔数、`dex2oat` 标记；`source` 记录样本 SHA 与证据路径 |
| `android/shield/src/main/java/dev/forgemirror/shield/yidun/YidunSignatures.java` | 特征加载与 JSON 解析；资产缺失时安全降级为空 |
| `android/shield/src/main/java/dev/forgemirror/shield/yidun/YidunProbe.java` | root/mount、逐线程 `TracerPid`/zombie、`NativeBridgeError`、模拟器路径/属性/Build、VMOS 服务、maps 标记 + ELF `e_machine` 过滤、Xposed 类与服务、fd readlink、`LD_PRELOAD`、云手机包名、code_cache DEX 魔数、`dex2oat` maps 特征 |
| `android/shield/src/main/java/dev/forgemirror/shield/ShieldDetect.java` | 接入通用检测链路；按 evidence 去重，规则 ID 保留 `yidun_` 前缀 |

规则 ID：`yidun_root`、`yidun_mount`、`yidun_debug`、`yidun_hook`、`yidun_xposed`、`yidun_injection`、`yidun_emulator`、`yidun_ld_preload`、`yidun_dex`。响应仍走 `ShieldResponse` 的 log/toast，没有 exit/kill 分支。

明确没有吸收：

- `exit_group(94)` 与失败自毁；
- 7-bit XOR 字符串混淆；
- 证书 ASN.1 链（本构建不可达）；
- OLLVM/VM 解释器（结论为 JNI 编组器）；
- 风险文案与 `NEDialog` UI。

### PKR1 下发

- `backend/pipeline/forgemirror/formats/rules.py`：PKR1 载荷新增可选 `yidun` 段；构建与加载都校验 schema、`source`（vendor/library/sample_sha256/evidence）、字符串长度、列表上限和嵌套深度；非法段整包拒绝。
- `backend/pipeline/forgemirror/protect.py`：默认规则包读取 `android/shield/src/main/assets/yidun-signatures.json`，随 `rules.pkr` 下发；规则版本升到 2，`config.rules_version` 同步。
- `ShieldRules`：把 `yidun` 段解析为 `YidunSignatures`，签名、解密、版本门控不变。
- `ShieldRuntime`：在检测启动前把 PKR1 特征注入 `ShieldDetect`。
- `ShieldDetect`：优先使用 PKR1 特征，缺失或为空时回退内置资产；日志 `source=pkr1|asset` 标明来源。
- `ShieldRuleUpdater`：服务端可为 `yidun_*` 规则单独配置响应。

端到端验证（Pixel 5 / Android 11）：

```text
protect 输出 rules.pkr version=2；open_rules 解出
  yidun vendor=NetEase Yidun su=28 emu_paths=54 dex_magic=8

设备日志：
ShieldRules: yidun signatures vendor=NetEase Yidun sample=8ff...
ShieldRules: loaded 2 rules version=2
ShieldDetect: yidun signatures injected from pkr1 vendor=NetEase Yidun ...
ShieldDetect: yidun signatures source=pkr1 vendor=NetEase Yidun ...
ShieldRuntime: native file hooks status=0
ShieldRuntime: dex loaded count=8 ...
ShieldRuntime: bootstrap ok state=4
ShieldDetect: finding yidun_root /system_ext/bin/su
ShieldDetect: finding yidun_mount mount:magisk:...
```

规则加载已前移到 native 文件钩子配置之前，确保来源日志可见；`source=pkr1` 证明运行时使用的是 PKR1 特征而不是内置资产。验证用的 protected APK 在 `artifacts/pkr1-yidun/`（git 忽略）。

### 远程更新

PKR1 远程更新的实现、设备结果与复现步骤见 `docs/evidence/2026-11-21-P3-pkr1-remote-update.md`。

## 验证（本项目实测）

```text
./gradlew :shield:testDebugUnitTest
BUILD SUCCESSFUL

ShieldPolicyPatternTest        5 项
ShieldArtTest                  3 项
ShieldChunkStoreTest          26 项
ShieldNativeFileHookTest       1 项
ShieldDetectTest               5 项
YidunProbeTest                 7 项
YidunSignaturesAssetTest       1 项
合计                          48 项，0 失败
```

PKR1 测试：

```text
backend/tests/pipeline/test_rules.py  9 项，0 失败
  含 yidun roundtrip、bad schema、missing source、bad leaf、真实资产往返

设备端 YidunProbeDeviceTest
  pkr1PayloadParsesWithProvenance       通过
  pkr1PayloadWithoutSourceIsRejected    通过
```

完整检查：`backend/pipeline/scripts/check.sh` 通过（容器向量、Python 88 项、C++ 向量、Gradle assemble）。

JSON 结构校验：

```text
schema forgemirror.yidun-signatures/1
su 28
emu_paths 54
emu_props 22
hook_maps 9
cloud ['com.bluestacks.', 'com.microvirt.', 'com.mumu.', 'com.netease.mumu.', 'com.androVM.', 'com.bignox.']
cloud_services ['VMOS_MANAGER_SERVICE']
dex_magic 8
dex2oat ['dex2oat']
```

### 设备矩阵

| 设备 | 环境 | 命中 | 结论 |
|---|---|---|---|
| Pixel 5（Android 11 / API 30） | 已 root，Magisk + Zygisk | `yidun_root` `/system_ext/bin/su`；`yidun_mount` `mount:magisk:...` | root/mount 真阳性；emulator/hook/xposed/injection/dex 均 0 误报 |
| Medium_Phone_API_37.0（API 37，arm64） | 标准 AVD | `yidun_emulator` `property:ro.kernel.qemu=1` | 模拟器真阳性；hook/xposed/injection/dex 均 0 误报 |

新增探针在两类设备上的结果：VMOS 服务未出现；maps 中无 Hook 标记，ELF 过滤未产生命中；`code_cache` 无 `.dex`，`dex2oat` 未映射进进程。

探针耗时（同一测试，最终版本）：Pixel 5 约 80–140 ms；API 37 模拟器约 540–580 ms（冷启动首轮 1.6 s）。首轮模拟器曾达 13 s，原因是每个属性都重新反射解析 `SystemProperties`；缓存反射句柄后恢复。

设备测试：`android/app/src/androidTest/java/dev/forgemirror/demo/YidunProbeDeviceTest.java`。

```bash
ANDROID_SERIAL=<serial> ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=dev.forgemirror.demo.YidunProbeDeviceTest
```

断言策略：真机不得出现 emulator 命中；模拟器必须出现 emulator 命中；两类设备都不得出现 hook/xposed/injection 命中。`code_cache` 中标准 DEX 允许（0.5），未知魔数或 `dex2oat` maps 视为误报；root 命中不设断言，取决于设备是否 root。

单测覆盖：su 路径、mount 行与标记去重、模拟器路径/Build/属性/包名、VMOS 服务、maps 行解析与 ELF `e_machine`（四种 ABI、大小端）、hook maps 分组、Xposed/SandHook 类、`LD_PRELOAD`、`TracerPid`/zombie、DEX 魔数分类与脱敏输出，以及资产来源元数据。

## 限制

1. **设备矩阵仍小**：目前只有 Pixel 5（Android 11，已 root）和 API 37 模拟器；更多 ROM/ABI 组合未覆盖，功能矩阵仍标 `prototype`。
2. 测试机装有 Zygisk，通用 `env_injection` 会命中（真阳性）；易盾 maps 标记不含 zygisk，因此 `yidun_injection` 未命中，符合预期。
3. `android.os.SystemProperties` 与 `ServiceManager` 走反射，Android 9+ hidden API 限制下可能返回空；VMOS 服务探针同样依赖 `ServiceManager`，未命中按无该服务处理。
4. `Seccomp=2` 是常见基线，未单独判风险；`NativeBridgeError` 只给 0.4 置信度。
5. `getPackagesForUid` 通常只返回同 UID 包，云手机包名检测覆盖面有限。
6. 易盾 ROM 品牌包名（`com.samsung.` 等）只作研究上下文，未接入扫描，避免大面积误报。
7. 通用 `env_*` 与易盾 `yidun_*` 可能对同一条件各记一条事件；evidence 相同的会去重，保留双规则是为了来源可追溯。
8. mount 命中已按标记去重：同一标记只报一条，避免 Magisk 多行挂载刷屏。
9. ELF 过滤在原样本 arm64 基础上扩展到 AArch64/ARM/x86/x86_64；APK 内 `!` 映射（如 `base.apk!lib/...so`）跳过，不读取 ELF 头。
10. DEX 检查只扫 `code_cache` 的 `.dex`：标准魔数 0.5，未知魔数 0.7；`dex2oat` 只在自身 maps 命中时 0.4，正常设备通常不出现。

## 下一步

1. 扩充设备矩阵：至少覆盖一个非 root 真机、一个厂商 ROM 和一个 32 位 ABI，确认无误报。
2. Yidun 特征更新的回滚与灰度策略，以及服务端规则版本与清单 `rule_version` 的一致性。
