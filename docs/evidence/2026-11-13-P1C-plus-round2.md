# 2026-11-13 P1-C+ 第二轮：五项遗留的解决记录

## 解决情况

| # | 遗留项 | 结果 |
|---|---|---|
| 1 | 通用 native 改写 | **已解决**：`ShieldClassLoader` 继承 `BaseDexClassLoader`（`InMemoryDexClassLoader` 是 final，不能继承），通过公开的 `DexPathList.makeInMemoryDexElements` 装配内存 DEX，并重载 `findLibrary` 把业务 `System.loadLibrary` 映射到 APK 内 `lib/<abi>/`。业务代码恢复标准 `System.loadLibrary("demo")`，JNI 成功 |
| 2 | API 26–28 无 `onActivityPreCreated` | **已实现未验证**：`ShieldInstrumentation` 在 `callActivityOnCreate` 前 patch Activity base context；API < 29 时从 `attachBaseContext` 安装。缺 API 26–28 真机，保持"implemented, untested" |
| 3 | `getApplication()` 强转失败 | **已解决**：`installOriginalApplication` 把 `ActivityThread.mInitialApplication` 和 `LoadedApk.mApplication` 换成原 Application。业务 `(HarnessApplication) getApplication()` 成功 |
| 4 | 7 DEX 压测 | **已解决**：`--extra-dex` 生成 12 DEX 容器（5 个 d8 合成 DEX），解密 206–213 ms，主/`:remote` 进程均正常 |
| 5 | 通用 AXML S6 / 原生 Core / key-service | **不在本轮**：P2 范围 |

## 关键实现

- `ShieldClassLoader.findLibrary`：遍历 `SUPPORTED_ABIS`，在 APK zip 内查 `lib/<abi>/<mapped>`，返回 `apkPath!/lib/<abi>/<name>`；不命中回退 super。
- Application 替换的连锁问题：swap 之后框架把生命周期回调 dispatch 给 original，adapter 必须注册在 original 上（第一版注册在 ShieldApplication 导致 inflate 崩溃）。同时保留 `onActivityCreated` 兜底。
- `build_protected_demo.py --extra-dex`：从 APK 重新收集业务 DEX + 附加 DEX，重写容器（复用 nonce_prefix/build_id 派生密钥）。

## 设备验证（Pixel 5 / API 30，12 DEX 受保护包）

```text
ShieldRuntime: dex loaded count=12 decryptMs=213 pssKb=115353 sdk=30
ShieldApplication: original Application installed: dev.forgemirror.demo.HarnessApplication
ShieldRuntime: activity context adapted: dev.forgemirror.demo.MainActivity
MainActivity: onCreate / onResume
:remote: dex loaded count=12 / Application installed / onCreate
```

UI dump：`Hello from C++ / app=HarnessApplication / provider rows=1`

即：标准 `System.loadLibrary`、`(HarnessApplication) getApplication()` 强转、AppCompat+ConstraintLayout XML、12 DEX、双进程，全部在受保护包内工作。

## 构建与测试

- 34 项 Python 测试、C++ 双端向量通过。
- `:app:assembleRelease`、`:shield:assembleRelease`、`:app:connectedDebugAndroidTest` 通过。

## 残余风险

- `installOriginalApplication` 依赖 `mInitialApplication`/`mPackageInfo`/`LoadedApk.mApplication` 反射（greylist，API 30 允许）；需按 API 级别回归，适配失败的 fallback 是 `getApplication()` 返回壳实例。
- `ShieldClassLoader` 的 `makeInMemoryDexElements` 反射依赖 `DexPathList` 布局；API 26–36 需矩阵验证。
- Instrumentation 路径未在真机 API 26–28 验证。
- 12 DEX 压测的附加 DEX 是空类；真实第三方应用的规模/复杂度未覆盖。
