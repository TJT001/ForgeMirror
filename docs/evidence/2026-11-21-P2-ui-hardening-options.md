# 2026-11-21 P2：前端加固选项暴露

## 范围

把当前 CLI/运行时已实现的加固功能接入 Web 任务表单，贯通
`UI → multipart API → tasks.options → worker CLI → 产物归档`。

## 表单字段

| UI 字段 | 传给 protect | 说明 |
|---|---|---|
| 输入 | `--apk` | `.apk` / `.aab` |
| Split APK | `--split` | 可重复，仅 APK 输入 |
| Device spec | `--device-spec` | 可重复，仅 AAB split |
| Profile | `--profile` | basic/enhanced/financial |
| 签名 | `--signing-mode` | customer_local/hsm |
| AAB 模式 | `--aab-mode` | universal/split |
| 内存加载库 | `--in-memory-libs` | 逗号分隔 |
| 签名算法 | `--alg` | ECDSA P-256/Ed25519 |
| 响应模式 | `--response` | log/toast/degrade/block |
| Shell 版本 | `--shell-version` | 高级项 |
| native 上限 | `--max-native-file-mb` | 1–4096 |
| 授权/事件 URL、事件 Token | `--auth-url`/`--event-url`/`--event-token` | 空值回退服务端 env |
| Core 自解密 | `--no-self-decrypt-core` | 关闭时传 |
| 双 PT_DYNAMIC 诱饵 | `--no-decoy-dynamic` | 关闭时传 |
| 破坏 section 名表 | `--keep-section-names` | 关闭时传 |
| Text 段自解密 | `--no-self-decrypt-text` | 关闭时传 |
| 运行时检测 | `--no-detection` | 关闭时传 |
| 不内置内容密钥 | `--no-key-asset` | 勾选时传 |

`--out`、`--build-id`、`--shield-aar`、`--key-dir`、`--sdk-root`、
`--build-tools`、`--bundletool` 属于服务端部署参数，不由浏览器传入；
`bundletool` 从 worker 的 `BUNDLETOOL` env 解析。

## 实现

| 位置 | 内容 |
|---|---|
| `frontend/src/App.vue` | 高级选项折叠面板、APK/AAB、split/device spec 多文件、布尔开关、SSE 进度与产物下载 |
| `api.createTask` | 解析 multipart 全部字段；校验 profile/signing/alg/response/aab_mode；保存 splits/device specs；选项写入 `tasks.options` |
| `migrations/0006_task_options.sql` | `tasks.options JSONB NOT NULL DEFAULT '{}'` |
| `store.Task` | `Options` 仅 worker 可见，任务 API 不返回（避免泄露 event token/路径） |
| `worker.build_protect_command` | 按 options 拼 CLI；空 auth/event 值回退 env |
| `worker.package_result` | 单 APK 直接返回；split/AAB/多 spec 打包 `protected-set.zip` |

## 验证

界面已在浏览器实际渲染并提交任务：

- 默认选项 app-debug.apk → `succeeded`，artifact 为 APK。
- 非默认选项（`detection=false`、`response=log`、`max_native_file_mb=64`、
  `no_key_asset=true`）→ 解包 `assets/shield/config.json` 得到对应值：
  ```json
  {"detection": false, "response": "log", "max_native_file_mb": 64, "key": ""}
  ```
- base + split APK → `protected-set.zip`，内含 `protected.apk`、split 清单和
  `protected_splits/00_split_signed.apk`。
- AAB + 2 个 device spec → `protected-set.zip`，内含 `batch.json`、
  `sets/00/*`、`sets/01/*`。
- `npm run build`（vue-tsc）、Go 测试、Python pipeline 93 项通过。

## 限制

1. 任务 API 不回显选项，前端不展示历史任务配置；重跑需重新填写。
2. split/batch 产物统一下载 ZIP；界面暂不拆分为逐 split 下载。
3. 事件 Token 存在 DB `tasks.options`，不进入任务 JSON；仍需数据库访问控制。
4. bundletool 路径由 worker env 提供，浏览器不能覆盖；AAB split 需部署环境安装。
5. 内容密钥复用 `--key-file` 与自定义 `--key-dir` 未暴露，保持服务端控制。
