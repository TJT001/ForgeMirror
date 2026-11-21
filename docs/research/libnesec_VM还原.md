> **来源**：`<external-research-dir>/sampleb/libnesec_OLLVM与VM还原.md`。
> 证据级别映射：观测→V，代码→S，推断→I，未知→U。产物 `artifacts/nesec_vm/` 相对 `<external-research-dir>/sampleb/`，不入本仓库。
> 结论：该解释器是 JNI 参数/返回编组器，不是保护业务逻辑的 VMP；不复刻（见 `docs/设计文档.md` §17.9）。

---

# libnesec.so 混淆还原：OLLVM 排查与签名解释器（VM）分析

- 日期：2026-11-21
- 目标：`artifacts/nesec_runtime_dump/libnesec_full.so`（IDB：`libnesec_full.so.i64`）
- 产物目录：`artifacts/nesec_vm/`

---

## 0. 结论先行

1. **libnesec 没有 OLLVM 控制流平坦化，也没有 MBA 指令替换。**
   全库 4,226 个函数中 3,664 个 `BR`（间接跳转）为 0，547 个只有 1 个 `BR`（尾调用/PLT thunk），
   只有 1 个函数 `BR` 数量异常（242 个）。
2. 那个异常函数不是平坦化，而是一个 **256 项 opcode 表、228 个 handler 的线索化解释器**。
3. 该解释器的调用方 `sub_A89B4` 在启动时遍历 JNI 签名串（`()V`、`()Z`、`(Landroid/os/Bundle;)V` 等），
   把极短的类型描述符（实测 `""`、`"L"`）喂给解释器；解释器尾部用 `'['`(0x5B) / `'L'`(0x4C) 判断 JNI 返回类型。
   → 它是 **JNI 参数/返回值的类型编组器**，不是保护业务逻辑的通用 VMP。
4. 因此“OLLVM 还原”这项工作的实际结论是：**没有可还原的 OLLVM**，本项可以关闭。
   libnesec 的混淆主体仍是：加密字符串表（§5.2）、加密 dex（运行时 in-memory 加载）、这个签名解释器。

---

## 1. 排查方法

### 1.1 全库指令特征扫描

脚本：`artifacts/nesec_vm/ollvm_scan.py`，输出：`ollvm_stats.json`。

统计每个函数的指令数、间接跳转（`BR`）、间接调用（`BLR`）、条件分支（`CBZ/CBNZ/TBZ/TBNZ`）、
条件选择（`CSEL/CSINC/CSINV/CSNEG`）、位运算密度（`EOR/AND/ORR`）。

`BR` 分布：

| BR 数量 | 函数数 |
|---|---|
| 0 | 3,664 |
| 1 | 547 |
| 2–3 | 13 |
| 4–10 | 1 |
| 11–50 | 1 |
| >50 | 1 |

OLLVM 平坦化必然产生大量 `BR`（跳表分派）或超长的条件链；本库不存在这种分布。

### 1.2 排除“伪混淆”特征

之前伪代码里看似混淆的片段，逐个确认是正常代码：

| 片段 | 实际含义 |
|---|---|
| `ORR X10, X21, #1` + `TST W8, #1` + `CSEL` | libc++ `std::string` 短字符串优化（指针低 bit 标记） |
| `MOV W8,#3; SDIV; ADD W8,W8,LSL#1; SUB` | 编译器把 `% 3` 优化成乘加 |
| `BL sub_Dxxxx` 后 `_UNKNOWN **` / 未初始化变量 | IDA 对 PLT/导入 thunk 的参数恢复失败，不是混淆 |
| 大量 `__usercall` / 巨型栈帧 | 函数边界被并进 VM 区域导致 |

---

## 2. 异常函数 = 线索化解释器

### 2.1 定位

- 24,028 字节、5,819 条指令、242 个 `BR`：`sub_BDE38`（实为整段解释器区域）。
- 入口：`0xBD698`（外部调用者 `sub_A89B4`，另一调用点 `sub_D334`/`0xbd694`）。
- 分派表：`0x17084`，256 项 `u16`；目标 = `0xBD914 + u16 * 4`。
- 所有 228 个唯一 handler 都落在 `0xBD914..0xC3B98`，是直接线索化（direct threading）：
  handler 结尾直接 `BR` 到下一个 opcode 的 handler，没有统一 dispatch 循环。

### 2.2 指令格式

```
u16 header : 低 8 位 = opcode，高 8 位 = 虚拟寄存器号
u16 operand: 立即数 / 偏移（按 opcode 解释）
```

依据（`0xBD914`，opcode 0x01）：

```
ADD X14, X13, #2        ; PC += 2
STR X14, [SP,#arg_C0]   ; 回写 PC
LDRH W13, [X13,#2]      ; 取下一 u16
AND X14, X13, #0xFF     ; opcode
ADR X15, sub_BD914
LDRH W16, [X17,X14,LSL#1]
ADD  X15, X15, X16,LSL#2
BR   X15                ; 直接跳 handler
```

即 `0x01` = “推进 PC，分派下一条”。

### 2.3 VM 上下文布局

由 `0xBD698` 序言与运行时 dump 对照得出（`sub_BD698(ctx, env, jcls, arg3, arg4)`）：

| 偏移 | 类型 | 含义（实测值示例） |
|---|---|---|
| +0x04 | u8 | 标志位（bit3 = 有局部变量） |
| +0x08 | u32 | 参数个数 argc |
| +0x0C | u32 | 3（常量/版本） |
| +0x10 | u32 | 虚拟寄存器总数 nreg（实测 3） |
| +0x14 | u32 | 0x72（实测） |
| +0x18 | std::string | 类型描述符 / 程序串（实测长度 1，内容 `"V"`） |

寄存器堆：

- `X21` = 基址；32 位槽在 `X21 + idx*4`，64 位槽在 `X21 + nreg*4 + idx*8`。
- `W28` = 当前指令头，`W28 >> 8` = 寄存器号。
- `X24` = 返回寄存器。
- `arg_C0` = PC。
- `X19` = JNIEnv，`X20` = ctx，`X26` = 描述符长度。

### 2.4 收尾块

`0xC3B98`（表项 0xFE）= VM 返回：

```
BL  sub_D47DC                  ; 计数/中断检查
LDRB W8, [类型串]
CMP  W8, #0x5B ('[')  /  #0x4C ('L')
BL  sub_C3E30                  ; JNI 值转换
BL  sub_ABC04
LDP X29, X30, ... ; RET
```

`'['` = 数组、`'L'` = 对象 —— 典型的 JNI 返回类型判断。

### 2.5 已确认语义的 handler（抽样）

| opcode | handler | 语义 |
|---|---|---|
| 0x01 | 0xBD914 | 推进 PC + 分派（NOP） |
| 0x36 | 0xBEC28 | 64 位比较：`v[a] == v[b] ? 0 : (v[a] < v[b] ? -1 : 1)` → 存 32 位槽 |
| 0x5F | 0xBDE38 | 读虚拟寄存器到 X24 → 结束（返回） |
| 0xFE | 0xC3B98 | VM 收尾（JNI 返回类型处理 + RET） |
| 0x10 | 0xC3B88 | 读虚拟寄存器到 X24 后进入收尾 |

其余 handler 分类（`vm_opcode_map.csv`）：

| 模板 | 数量 |
|---|---|
| 仅含计数/边界检查 | 78 |
| 未命中模板（需人工） | 71 |
| 32 位写回 + 检查 | 15 |
| 跳转类 | 11 |
| 跳转 + 检查 | 10 |
| 32/64 位写回 + 比较 | 3 |
| 跳转 + JNI 调用 | 3 |
| 其他组合 | 9 |

### 2.6 函数边界修复

原始 IDB 把整个解释器并成一个 24KB 函数，导致 228 个 handler 的伪代码全部错误。
脚本 `vm_fix_bounds.py` 删除错误定义、按 handler 起点重建边界并重设 `func_end`：

- 重建 **229 个函数**，区域总长 **19,988 字节**；
- 反编译成功 **195/229**（其余为与相邻 handler 共享尾部/不可达块）；
- 伪代码导出：`artifacts/nesec_vm/handlers/`（195 个 `.c`）。

---

## 3. 运行时观测

### 3.1 调用次数与入参

脚本 `/tmp/wm_tools/vm_trace.js`、`vm_ctx.js`、`vm_str.js`，`frida -U -f com.example.sampleb`：

- 冷启动 45s 内 VM 入口只被调用 **2 次**。
- 第 1 次：`nreg=3, argc=1, flags=1`，程序串长度 1（`"V"`）。
- 第 2 次：`nreg=4, argc=2, flags=4`，程序串长度 2。
- 在 `0xBD740`（`strlen`）处直接读取：调用 1 的串为空（首字节 0x00），调用 2 的串为 `"L"`（0x4C 0x00）。

ctx 原始内存（第 1 次）：

```
8c420000 01000000 01000000 03000000 03000000 72000000
02 56 00 ...            <- +0x18: std::string 标志 0x02（短串，len=1），数据 "V"
```

### 3.2 调用者

`sub_A89B4`（被 `sub_A933C`、`sub_DA380` 调用）遍历一组 JNI 签名：

```
"()V" / "()Z" / "(Landroid/os/Bundle;)V" / ...
```

对每个签名调用一次解释器（`0xA8FBC: BL sub_BD698`），并用 `sub_6E4EC` 做字符串比较。

结论：解释器服务于 **JNI 方法/字段适配层的构建**，输入是类型描述符，输出是调用适配闭包。

---

## 4. opcode 全表

256 项映射见 `artifacts/nesec_vm/vm_opcode_map.csv`（列：opcode_hex / opcode_dec / handler_hex / pseudo_tags），
原始表见 `vm_opcodes.json`。节选：

```
00:c0134 01:bd914 02:beb40 03:c053c 04:c20a4 05:c06c0 06:c275c 07:c1010
08:bdeb4 09:c2b14 0a:c211c 0b:c34c4 0c:c3660 0d:c0708 0e:beedc 0f:be05c
10:c3b88 11:beac8 12:bdbdc 13:c327c 14:bff40 15:c1560 16:c17c0 17:c22c4
...
36:bec28 (cmp64)   5f:bde38 (return)   fe:c3b98 (epilogue)
```

256 个表项 → 228 个唯一 handler；同一 handler 被多个 opcode 复用的有 16 个 opcode 指向同一地址等。

---

## 5. 对“是否分析完毕”的影响

- “OLLVM 还原”不再是缺口：**不存在**。
- 仍需人工的只剩 VM 语义：195 个已导出，其中 71 个未命中模板、18 个 JNI/跳转类需要逐条读；
  但这些只影响 JNI 适配层的细节，**不涉及风险判定逻辑**（判定逻辑在 `sub_9D304`/`sub_A3848`/`sub_CDCC8` 等普通函数里）。
- 结论：如果目标是“说清加固能力与判定条件”，VM 语义可以按需深挖，不是阻塞项。

---

## 6. 复现

```bash
# 1. 全库特征扫描（IDA MCP）
#    py_exec_file artifacts/nesec_vm/ollvm_scan.py
# 2. 导出 opcode 表与 handler 伪代码
#    py_exec_file artifacts/nesec_vm/vm_dump.py
# 3. 修复函数边界后重新导出
#    py_exec_file artifacts/nesec_vm/vm_fix_bounds.py
# 4. 运行时抓 VM 入参
frida -U -f com.example.sampleb -l /tmp/wm_tools/vm_trace.js -q -t 45 --runtime=v8
```

注：`vm_fix_bounds.py` 会修改 IDB 的函数定义；如需保留原始状态，先备份 `libnesec_full.so.i64`。
