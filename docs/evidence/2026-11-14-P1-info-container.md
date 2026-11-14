# 2026-11-14 P1：INFO- 规则容器兼容

## 范围

参考壳用 `info.y` 保存规则/字符串资产：`INFO-` 魔数、16 字节 MD5、1 字节节数、
每条 12 字节的 `(offset, flags, size)` 表，正文为规则与字符串。本项目只实现
**结构解析与完整性校验**，供 `legacy-inspect` 分析存量样本；不实现参考壳的
YARA 虚拟机，也不在加固产物中生成 `info.y`。

## 实现

| 位置 | 内容 |
|---|---|
| `formats/infoy.py` | 校验 `INFO-`、节数上限、节区间越界、正文 MD5；解析节表和可打印字符串 |
| `cli.py legacy-inspect --info-y` | 输出 `digest`、`sections`、`strings`，解析失败返回非零 |
| `tests/pipeline/test_infoy.py` | 正常解析、摘要不匹配拒绝；CLI 用同一构造样本手工验证 |

## 验证

```text
$ legacy-inspect --info-y /tmp/demo_info.y
{
  "info_y": {
    "digest": "d274101c8e70cbdad6f5057758738370",
    "sections": [{"flags": 1, "index": 0, "offset": 34, "size": 13}],
    "strings": ["frida", "xposed"]
  },
  "ok": true
}
```

Python pipeline 68 项测试通过。

## 限制

1. 只解析容器和字符串，不执行参考壳的 YARA 规则，不做规则命中的事件/响应。
2. 未实现规则热更新、签名/加密规则体；若真实样本的 `info.y` 规则区另有编码，
   需要按样本再扩展。
3. `classes.dve` 仍由既有 `formats/legacy.parse_classes_dve` 解析，本模块不重复实现。
