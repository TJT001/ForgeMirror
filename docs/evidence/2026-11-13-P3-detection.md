# 2026-11-13 P3：运行时检测、Toast 响应与规则热更新

## 范围

P0 运行时环境检测；检测事件与响应分级（默认 Toast，**不 kill**）；服务端配置；
PKR1 规则包热更新与版本门控。

## 实现

| 模块 | 内容 |
|---|---|
| `ShieldDetect.java` | `/proc/self/maps`、`/proc/self/task/*/comm`、TracerPid/Debug、root 路径、Build/模拟器设备、Xposed 类加载 |
| `ShieldResponse.java` | `log` / `toast` 两种响应；聚合 kind 后主线程 Toast；无 kill/exit/block 分支 |
| `ShieldServerConfig.java` | 缓存服务端 `detection` / `response`；只接受 `log`/`toast` |
| `ShieldProcess.java` | 检测/更新仅在主进程执行，避免远端进程重复 Toast/写文件 |
| `ShieldRuleUpdater.java` | 后台拉取 `/api/v1/config` 与 `/api/v1/rules/latest`；PKR1 验签/解密/版本门控后原子落盘，下次启动生效 |
| `ShieldRules.java` | 优先加载 `files/shield/rules.remote.pkr`；失败回退内置包；暴露 rule version |
| `0004_rules.sql` / `store/rules.go` | `rule_packages`、`client_config` 表 |
| `api.go` | `GET/POST /api/v1/config`、`POST /api/v1/rules`、`GET /api/v1/rules/latest` |

## 检测项

| rule | 证据 |
|---|---|
| `env_frida` | maps 中 frida/gum-js/linjector；线程名 `gum-js-loop`/`pool-frida` |
| `env_xposed` | maps 中 xposed/lsposed/edxposed；XposedBridge 等类 |
| `env_injection` | maps 中 zygisk/riru/magisk/substrate |
| `env_unpacker` | maps 中 youpk/fupk/fart/dumpdex/yarfahook |
| `env_hook` | maps 中 libhook/inlinehook/bhook/dobby |
| `env_debugger` | `Debug.isDebuggerConnected`/`waitingForDebugger`、`TracerPid>0` |
| `env_root` | su/Superuser/Magisk 路径、`Build.TAGS=test-keys` |
| `env_emulator` | Build fingerprint/model/hardware/product、qemu/goldfish 设备 |

命中后写入 `runtime_detection` 事件；响应默认 Toast：
`ForgeMirror 检测到运行环境异常：<kind 列表>`。

## 验证

### 设备（Pixel 5 / API 30）

```text
ShieldDetect: no runtime findings          # 真实设备，无误报
ShieldRuleUpdater: server config applied response=toast
ShieldRuleUpdater: remote rules stored version=2
ShieldRules: loaded remote rules version=2
ShieldRules: yara matched: fm_demo_jni_v2 in lib/arm64-v8a/libdemo.so
ShieldEvents: recorded rule_hit/fm_demo_jni_v2 queued=4
```

Toast（调试触发，截图 `artifacts/p3-events/detection-toast.png`）：

```text
ShieldResponse: response mode=toast kinds=demo
ForgeMirror 检测到运行环境异常：demo
```

服务端配置关闭检测后，下次启动：

```text
ShieldDetect: detection disabled
```

规则版本门控：`current=2` 时 `GET /rules/latest` 返回 `204`。

### 接口

```bash
# 服务端配置
curl -H 'X-Client-Token: dev-client-token' \
  'http://127.0.0.1:8080/api/v1/config?app_package=dev.forgemirror.demo'

# 发布 PKR1
curl -X POST -H 'X-Client-Token: dev-client-token' \
  --data-binary @rules-v2.pkr \
  'http://127.0.0.1:8080/api/v1/rules?app_package=dev.forgemirror.demo&version=2'
```

### 测试

```text
ShieldDetectTest       3 项（maps/线程/Build 分类与排除）
ShieldChunkStoreTest   9 项
ShieldPolicyPatternTest 4 项
Python pipeline       54 项
Go build / vet        通过
```

## 限制

1. 未实现匿名可执行段/ART 符号级深度检测；Frida 17 等不留下明显 maps 字符串时可能漏报。
2. 响应只有 `log`/`toast`；按需求**不实现 kill/exit/block**。
3. 远端进程暂不执行检测/上报（仅主进程），避免重复；后续可做跨进程汇聚。
4. 规则热更新下次进程启动生效；配置缓存同样下次启动完全生效。
5. 服务端为 dev HTTP + 静态 `X-Client-Token`；生产需 TLS/mTLS 与请求签名。
6. 服务端上传只校验 PKR1 magic，签名/密钥绑定由客户端验签保证。
