# 铸镜 ForgeMirror

加固技术研究与复现平台，通过独立实现追求可验证的行为等价。

## 项目结构

- frontend/src：Web 界面，应用上传、加固配置、任务状态、产物下载和研究结果展示。
- backend/cmd、backend/internal、backend/pipeline、backend/tests：Go/Gin API、PostgreSQL/pgx 存储、Python 加固流水线与测试。
- android/app：Studio 标准 Android 工程；src/main/java 为 Java，src/main/cpp 为原生代码，src/test 与 src/androidTest 为测试。
- android/shield：运行时加固库（Java + C++17），含内存 ELF/DEX 加载、Hook 后端、PKR1 规则、检测与事件。
- docs：设计、实现原则、开发环境、格式、证据和 research 研究资料。

根 artifacts/ 按需产生并由 Git 忽略；研究样本的 dump、伪代码和等价代码留在外部目录。

## 当前状态

- Android：容器 v2、内存 DEX/ELF 加载、动态 TLS、Dobby（x86_64）/ShadowHook（arm/arm64）后端、16 KB 页、透明文件保护、PKR1 规则包、运行时检测与事件队列均已实现并有设备/主机证据。
- 检测：通用 `env_*` 规则 + 易盾来源的 `yidun_*` 规则；签名特征可随 PKR1 下发并在下次进程启动生效，已实测 v2→v3→v4 远程更新、篡改拒绝和版本门控。
- 后端：Go API、PostgreSQL、认证/事件/规则/配置接口已实现；PKR1 上传与版本门控可用。
- 流水线：S0–S8、APK/AAB、universal/default split、多 device-spec 批量、容器/策略/规则/清单、16 KB 对齐与 S8 闸门均有测试覆盖。
- 前端：上传/加固选项/任务进度/产物下载/安全事件页面已实现，已与 API/worker 联调。

## 技术选型

Vue 3 + TypeScript + Vite + Element Plus；Go + Gin + PostgreSQL/pgx；Python worker 与流水线；Android Java + C++17。详见 [架构选型](docs/架构选型.md)。

## 常用验证

```bash
# Android 单元测试
cd android && ./gradlew :shield:testDebugUnitTest

# 设备测试（示例：易盾探针）
ANDROID_SERIAL=<serial> ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=dev.forgemirror.demo.YidunProbeDeviceTest

# 后端 + 流水线全量检查
backend/pipeline/scripts/check.sh
```

## 文档

- [独立实现原则](docs/实现原则.md)
- [设计文档](docs/设计文档.md)
- [研究证据：参照样本 A（梆梆 libDexHelper）](docs/research/libDexHelper_架构还原.md)
- [研究证据：参照样本 B（网易易盾 libnesec）](docs/research/libnesec_易盾加固还原.md)
  - [检测链路实测](docs/research/libnesec_检测实测.md)、[证书链分析](docs/research/libnesec_证书链分析.md)、[VM 还原](docs/research/libnesec_VM还原.md)、[函数分类](docs/research/libnesec_函数分类.md)
- [规则包格式](docs/formats/rules-v1.md)
- [16 KB 页适配](docs/evidence/2026-11-21-P2-16kb.md)
- [split APK / AAB](docs/evidence/2026-11-21-P2-split-aab.md)
- [自研 loader 动态 TLS](docs/evidence/2026-11-21-P2-tls-relocation.md)
- [x86_64 hook 与 API 37](docs/evidence/2026-11-14-P1-api37-hooks.md)
- [前端加固选项](docs/evidence/2026-11-21-P2-ui-hardening-options.md)
- [开发环境](docs/开发环境.md)
- [依赖登记](docs/components.lock.json)

研究文档中的旧相对路径以 `/Users/taylee/SourceCode/pentest/zhiji` 和 `/Users/taylee/SourceCode/pentest/waimai` 为准。原目录说明归档在 docs/初始目录说明归档.md，仅作历史资料。
