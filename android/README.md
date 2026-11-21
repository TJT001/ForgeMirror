# Android

使用 Android Studio 打开本目录。包名 `dev.forgemirror.demo`，minSdk 26，compileSdk/targetSdk 37，Java 11、C++17；AGP 9.5.1、Gradle 9.6.0、CMake 3.22.1，NDK 28.2.13676358。

## 模块

- `app/`：宿主与测试 Harness；`src/main/java` 为 Java 入口，`src/main/cpp` 为 demo 原生库。
- `shield/`：运行时加固库。
  - `src/main/java/dev/forgemirror/shield`：容器、内存加载、透明文件、规则、检测、事件与响应。
  - `src/main/java/dev/forgemirror/shield/yidun`：易盾来源的检测特征与探针，规则 ID 带 `yidun_` 前缀。
  - `src/main/cpp`：ELF 加载器、Dobby/ShadowHook 后端、TLS、YARA JNI 与自解密。
  - `src/main/assets/yidun-signatures.json`：易盾特征数据，PKR1 缺失时作为回退。
- `app/src/test`、`shield/src/test`：JVM 单元测试；`app/src/androidTest` 为设备测试。

## 构建与测试

```bash
./gradlew :shield:testDebugUnitTest

ANDROID_SERIAL=<serial> ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=dev.forgemirror.demo.YidunProbeDeviceTest
```

设备测试结果、限制与复现步骤记录在 `../docs/evidence/`。对外原生接口采用 C ABI，遵循 `../docs/实现原则.md`。
