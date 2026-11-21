# 2026-11-21 P3：PKR1 远程规则更新

## 范围

验证 PKR1 规则的远程发布、客户端拉取、验签/解密、版本门控、原子落盘，以及 `yidun` 检测特征随包更新。客户端按设计在下次进程启动时生效。

## 实现

| 位置 | 内容 |
|---|---|
| `backend/pipeline/forgemirror/formats/rules.py` | 载荷新增可选 `yidun` 段；构建与加载两侧校验 schema、`source`、字符串长度、列表上限和嵌套深度 |
| `backend/pipeline/forgemirror/protect.py` | 默认规则包嵌入 `yidun-signatures.json`，规则版本 2，`config.rules_version` 同步 |
| `backend/pipeline/forgemirror/cli.py` | `protect --key-file` 复用内容密钥，保证远程包与已安装 APK 使用同一 `K_content` |
| `backend/internal/api/api.go` | 服务端策略白名单增加 `yidun_*` |
| `ShieldRules` / `ShieldRuntime` / `ShieldDetect` | 解析 `yidun` 段、在检测启动前注入、优先于内置资产 |
| `ShieldRuleUpdater` | 拉取 `/api/v1/config` 与 `/api/v1/rules/latest`；验签/解密/版本门控后原子写入 `rules.remote.pkr` |

## 环境

- PostgreSQL 容器 + `go run ./cmd/api`，监听 `127.0.0.1:8080`。
- 设备通过 `adb reverse tcp:8080 tcp:8080` 访问主机。
- protected APK：`--event-url http://127.0.0.1:8080 --event-token dev-client-token --key-file artifacts/pkr1-yidun/keys/k_content.bin`。
- 设备：Pixel 5，Android 11 / API 30，已 root（Magisk + Zygisk）。

## 结果

| 步骤 | 结果 |
|---|---|
| 发布 v3 | `POST /api/v1/rules?...&version=3` → 201；`latest current=2` → 200/8456 B；`current=3` → 204 |
| 首次启动 | 内置 v2 加载；更新器拉取 v3，`remote rules stored version=3`，`rules.version=3` |
| 二次启动 | `loaded remote rules version=3`，`captured=remote-test-2026-11-21`，`source=pkr1` |
| 篡改 v4 | 翻转密文 1 字节后发布；`rules update failed: SecurityException: signature invalid`；本地保持 v3，`rules.remote.pkr` 未覆盖 |
| 合法 v4 | 拉取并落盘 `version=4`；下一次启动加载 `captured=remote-v4-recovery`、`version=4` |
| 版本门控 | `current=3` → 200；`current=4` → 204 |
| 服务端策略 | `policies:{"yidun_root":"log"}` 被接受并可回读；随后重置为空 |

## 设备日志

```text
# 首次启动：内置 v2 → 拉取 v3
ShieldRules: loaded 2 rules version=2
ShieldRuleUpdater: server config applied response=toast
ShieldRules: yidun signatures ... captured=remote-test-2026-11-21
ShieldRules: loaded 2 rules version=3
ShieldRuleUpdater: remote rules stored version=3

# 二次启动：加载远程 v3
ShieldRules: loaded remote rules version=3
ShieldDetect: yidun signatures source=pkr1 ... captured=remote-test-2026-11-21

# 篡改 v4：拒绝
ShieldRuleUpdater: rules update failed: java.lang.SecurityException: signature invalid
# rules.version 仍为 3

# 合法 v4：落盘并在下一次启动加载
ShieldRuleUpdater: remote rules stored version=4
ShieldRules: loaded remote rules version=4
ShieldDetect: yidun signatures source=pkr1 ... captured=remote-v4-recovery
```

## 复现

```bash
# 1. 启动数据库与 API
docker compose -f backend/docker-compose.yml up -d postgres
(cd backend && go run ./cmd/api) &

# 2. 设备端口反向映射
adb reverse tcp:8080 tcp:8080

# 3. 打包并发布 v3（使用与已安装 APK 相同的 k_content/build_id/私钥）
#    完整脚本见 docs/evidence/2026-11-21-P3-yidun-detection.md 的 PKR1 小节
curl -X POST -H 'X-Client-Token: dev-client-token' \
  --data-binary @/tmp/rules-v3.pkr \
  'http://127.0.0.1:8080/api/v1/rules?app_package=dev.forgemirror.demo&version=3'

# 4. 安装带 event_url 的 protected APK，启动两次（首次拉取，二次生效）
# 5. 观测
adb logcat -s ShieldRuleUpdater:I ShieldRules:I ShieldDetect:I
```

## 限制

1. 远程规则在下次进程启动生效，不做热替换。
2. dev HTTP + 静态 `X-Client-Token`；生产需 TLS/mTLS 与请求签名。
3. 服务端只按版本号返回最新包，没有回滚/灰度/撤回接口。
4. 服务端上传只校验 PKR1 magic；真实性与密钥绑定由客户端验签保证。
5. 本次 v3/v4 的 `captured` 是人为标记，用于区分来源，不代表检测特征内容变化。
