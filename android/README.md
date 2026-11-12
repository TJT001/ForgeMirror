# Android

使用 Android Studio 打开本目录。当前为 Native C++ 模板，包名 dev.forgemirror.demo，minSdk 26，compileSdk/targetSdk 37，Java 11、C++17；AGP 9.5.1、Gradle 9.6.0、CMake 3.22.1，具体以工程配置为准。NDK 尚未在 app 配置显式固定。

- app/src/main/java：Java 入口，当前 MainActivity 加载 demo 原生库。
- app/src/main/cpp：CMakeLists.txt 和 native-lib.cpp，提供 stringFromJNI 模板调用。
- app/src/test、app/src/androidTest：本地和设备测试。

后续在此标准结构内实现，不另建平行 java/native 目录。对外原生接口采用 C ABI，遵循 ../docs/实现原则.md。

本次只检查配置及 JNI 入口，未执行 Gradle 构建或设备部署。已有 build 目录不能单独视为端到端验证通过。
