# 后端

Go/Gin 单体 API、PostgreSQL/pgx、Python 加固流水线。

## 目录

- `cmd/api`：授权、事件、规则包与客户端配置 API；启动时执行 `migrations/`。
- `internal/`：API、认证、存储与配置。
- `pipeline/forgemirror`：S0–S8、APK/AAB 处理、容器/策略/规则/清单编解码。
- `pipeline/scripts/check.sh`：流水线、Python、C++ 向量和 Gradle 构建的一键检查。
- `tests/pipeline`：Python 单元与格式向量测试。

## 本地运行

```bash
docker compose up -d postgres
go run ./cmd/api
```

默认配置：

| 环境变量 | 默认值 |
|---|---|
| `PORT` | `8080` |
| `DATABASE_URL` | `postgres://forgemirror:forgemirror_dev@localhost:5432/forgemirror?sslmode=disable` |
| `MIGRATIONS_DIR` | `migrations` |
| `DATA_DIR` | `data` |
| `CLIENT_TOKEN` | `dev-client-token` |

规则包上传后落在 `DATA_DIR/rules/<package>/<version>.pkr`；客户端通过 `GET /api/v1/rules/latest` 按版本门控拉取。

## 加固任务参数

`POST /api/v1/tasks` 为 multipart：`file`（.apk/.aab）、可选多个 `splits` 和
`device_specs`，以及 profile、signing_mode、aab_mode、认证/事件、自解密、检测、
响应、算法、内存库等加固选项。选项保存在 `tasks.options`，worker 负责拼
`forgemirror.cli protect` 命令；split/AAB/多 device-spec 的产物打包为
`protected-set.zip`，单 APK 直接返回 APK。

## 验证

```bash
go build ./...
go vet ./...
pipeline/scripts/check.sh
```

设计见 `../docs/设计文档.md`，规则格式见 `../docs/formats/rules-v1.md`，PKR1 远程更新证据见 `../docs/evidence/2026-11-21-P3-pkr1-remote-update.md`。
