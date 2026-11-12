# 铸镜 ForgeMirror

加固技术研究与复现平台，通过独立实现追求可验证的行为等价。

## 项目结构

- frontend/src：Web 界面，应用上传、加固配置、任务状态、产物下载和研究结果展示。
- backend/cmd、backend/internal、backend/pipeline、backend/tests（按需建立）：API、加固流水线、任务与产物管理、授权和事件服务；初期单体组织。
- android/app：Studio 标准 Android 工程；src/main/java 为 Java，src/main/cpp 为原生代码，src/test 与 src/androidTest 为测试。
- docs：设计、实现原则、开发环境、依赖登记和 research 研究证据。

Android 已由 Studio 创建 Native C++ 工程；前后端目前为目录骨架。测试放各模块内，按实际代码再细分。根 artifacts/ 按需产生并由 Git 忽略。

## 技术选型

Vue 3 + TypeScript + Vite + Element Plus；Go + Gin + PostgreSQL/pgx；Python worker 与流水线；Android Java + C++17。详见 [架构选型](docs/架构选型.md)。前后端尚未初始化。

## 文档

- [独立实现原则](docs/实现原则.md)
- [设计文档](docs/设计文档.md)
- [研究证据](docs/research/libDexHelper_架构还原.md)
- [开发环境](docs/开发环境.md)
- [依赖登记](docs/components.lock.json)

研究文档中的旧相对路径以 /Users/taylee/SourceCode/pentest/zhiji 为准。原目录说明归档在 docs/初始目录说明归档.md，仅作历史资料。

## 恢复 Codex 会话

运行 `codex resume 01a1ce18-3360-7c70-ac0a-29db08f0bb59 --cd /Users/taylee/SourceCode/ForgeMirror`。
