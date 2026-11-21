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
| `android/shield/src/main/assets/yidun-signatures.json` | 28 条 su 路径、mount 标记、逐线程调试标记、9 条 hook maps 标记、类/服务、fd/LD_PRELOAD 标记、54 条模拟器路径、22 条模拟器属性、云手机包名前缀；`source` 记录样本 SHA 与证据路径 |
| `android/shield/src/main/java/dev/forgemirror/shield/yidun/YidunSignatures.java` | 特征加载与 JSON 解析；资产缺失时安全降级为空 |
| `android/shield/src/main/java/dev/forgemirror/shield/yidun/YidunProbe.java` | root/mount、逐线程 `TracerPid`/zombie、`NativeBridgeError`、模拟器路径/属性/Build、maps、Xposed 类与服务、fd readlink、`LD_PRELOAD`、云手机包名 |
| `android/shield/src/main/java/dev/forgemirror/shield/ShieldDetect.java` | 接入通用检测链路；按 evidence 去重，规则 ID 保留 `yidun_` 前缀 |

规则 ID：`yidun_root`、`yidun_mount`、`yidun_debug`、`yidun_hook`、`yidun_xposed`、`yidun_injection`、`yidun_emulator`、`yidun_ld_preload`。响应仍走 `ShieldResponse` 的 log/toast，没有 exit/kill 分支。

明确没有吸收：

- `exit_group(94)` 与失败自毁；
- 7-bit XOR 字符串混淆；
- 证书 ASN.1 链（本构建不可达）；
- OLLVM/VM 解释器（结论为 JNI 编组器）；
- 风险文案与 `NEDialog` UI。

## 验证（本项目实测）

```text
./gradlew :shield:testDebugUnitTest
BUILD SUCCESSFUL

ShieldPolicyPatternTest        5 项
ShieldArtTest                  3 项
ShieldChunkStoreTest          26 项
ShieldNativeFileHookTest       1 项
ShieldDetectTest               5 项
YidunProbeTest                 5 项
YidunSignaturesAssetTest       1 项
合计                          46 项，0 失败
```

JSON 结构校验：

```text
schema forgemirror.yidun-signatures/1
su 28
emu_paths 54
emu_props 22
hook_maps 9
cloud ['com.bluestacks.', 'com.microvirt.', 'com.mumu.', 'com.netease.mumu.', 'com.androVM.', 'com.bignox.']
```

### 设备矩阵

| 设备 | 环境 | 命中 | 结论 |
|---|---|---|---|
| Pixel 5（Android 11 / API 30） | 已 root，Magisk + Zygisk | `yidun_root` `/system_ext/bin/su`；`yidun_mount` `mount:magisk:...` | root/mount 真阳性；emulator/hook/xposed/injection 0 命中 |
| Medium_Phone_API_37.0（API 37，arm64） | 标准 AVD | `yidun_emulator` `property:ro.kernel.qemu=1` | 模拟器真阳性；hook/xposed/injection 0 命中 |

探针耗时（同一测试）：Pixel 5 约 74 ms；API 37 模拟器约 364 ms。首轮模拟器约 13 s，原因是每个属性都重新反射解析 `SystemProperties`；缓存反射句柄后降到 364 ms。

设备测试：`android/app/src/androidTest/java/dev/forgemirror/demo/YidunProbeDeviceTest.java`。

```bash
ANDROID_SERIAL=<serial> ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=dev.forgemirror.demo.YidunProbeDeviceTest
```

断言策略：真机不得出现 emulator 命中；模拟器必须出现 emulator 命中；两类设备都不得出现 hook/xposed/injection 命中。root 命中不设断言，取决于设备是否 root。

单测覆盖：su 路径、mount 行与标记去重、模拟器路径/Build/属性/包名、hook maps 分组、Xposed/SandHook 类、`LD_PRELOAD`、`TracerPid`/zombie，以及资产来源元数据。

## 限制

1. **设备矩阵仍小**：目前只有 Pixel 5（Android 11，已 root）和 API 37 模拟器；更多 ROM/ABI 组合未覆盖，功能矩阵仍标 `prototype`。
2. 测试机装有 Zygisk，通用 `env_injection` 会命中（真阳性）；易盾 maps 标记不含 zygisk，因此 `yidun_injection` 未命中，符合预期。
3. `android.os.SystemProperties` 与 `ServiceManager` 走反射，Android 9+ hidden API 限制下可能返回空；API 37 模拟器上 `ro.kernel.qemu` 可读，其他 ROM 需逐项确认。
4. `Seccomp=2` 是常见基线，未单独判风险；`NativeBridgeError` 只给 0.4 置信度。
5. `getPackagesForUid` 通常只返回同 UID 包，云手机包名检测覆盖面有限。
6. 易盾 ROM 品牌包名（`com.samsung.` 等）只作研究上下文，未接入扫描，避免大面积误报。
7. 通用 `env_*` 与易盾 `yidun_*` 可能对同一条件各记一条事件；evidence 相同的会去重，保留双规则是为了来源可追溯。
8. mount 命中已按标记去重：同一标记只报一条，避免 Magisk 多行挂载刷屏。
9. maps 只做路径/标记匹配，未实现 libnesec 的 AArch64 ELF `e_machine` 过滤；`VMOS_MANAGER_SERVICE` 服务探针也未接入。

## 下一步

1. 扩充设备矩阵：至少覆盖一个非 root 真机、一个厂商 ROM 和一个 32 位 ABI，确认无误报。
2. 把易盾增量特征接入 PKR1 规则包版本门控，支持远程更新。
3. 评估 DEX 魔数/`dex2oat` 检查是否并入容器完整性原型（DET-04）。
