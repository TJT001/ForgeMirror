> **来源**：`<external-research-dir>/sampleb/libnesec_标志位与检测实测.md`。
> 证据级别映射：观测→V，代码→S，推断→I，未知→U。产物 `artifacts/...` 相对 `<external-research-dir>/sampleb/`，不入本仓库。
> 关联规格：`docs/设计文档.md` §17.9；实现：`android/shield/src/main/java/dev/forgemirror/shield/yidun/`。

---

# libnesec 标志位与检测链路实测

- 日期：2026-11-21
- 设备：已 root（Magisk），Frida 17 注入
- 产物：`artifacts/nesec_flags/`（脚本、块列表、检测命中 CSV）

---

## 0. 方法论修正（重要）

之前用**函数入口**下桩判断“某检测是否执行”，结论不可靠。易盾会直接跳到函数内部的**冷块**执行：

- `sub_A4CDC`：入口命中 1 次，但 `sub_A460C`（它的调用者）5 个块全部 0 命中 → 它不是从正常调用链进来的，而是 ART 回调直调。
- `sub_A413C`：入口 0 命中，内部块 `0xA4410` 命中 1 次。
- `sub_9D304`：入口 0 命中，但其内部 `0x9DE80/0x9DEF8` 被 wrapper 的 `lr` 证明执行过。

**结论：后续所有“是否执行”的判断必须用块级下桩或 Stalker，不能只看函数入口。**

---

## 1. 全局上下文结构

指针 `0x733ba28ff8`（`sub_D2CF8` 返回的单例），快照 0x120 字节：

| 偏移 | 内容 |
|---|---|
| `+0x00` | `std::string` 包名 `com.example.sampleb`（flag=0x2A，len=19） |
| `+0x18` | `std::string` 应用类 `cn.fly.FlyApplication` |
| `+0x30` | qword `0x31`（字符 '1'，疑似 debug 标志） |
| `+0x38` | qword `0x20` |
| `+0x40` | 指针 `0x728ba44350`（未解析） |
| `+0x48` | `std::string` 设备标识 1：`C146E1191B587466`（16 字节） |
| `+0x60` | `std::string` 设备标识 2：`9513175DAC7AA4A8`（16 字节） |
| `+0x78–0x9F` | 0 |
| `+0xA0–0x120` | 0/1 标志位区（检测结果），`+0x101` 启动后由 0 变 1 |

快照在 t=8s / 15s / 25s 完全相同 → 该结构在启动早期填完后不再变化。

---

## 2. `sub_A4CDC` 门控实测

执行时刻结构指针 `0x733ba28ff8`：

| 偏移 | 实测 | 代码位置与效果 |
|---|---|---|
| `+0xD8` | 1 | `0xA4D14` `CBNZ` → 跳过 `sub_83428/sub_D73FC` |
| `+0xE0` | 1 | `0xA4D34` `CBZ` 不跳 → 进入 `sub_D88DC` 检查 |
| `+0xED` | 0 | `0xA4D54` `CBZ` → 跳到 `0xA4E60` |
| **`+0x101`** | **0** | `0xA4E60` `CBZ` → 直接到 `0xA4FB8` 返回 |

因此：类名解码（`0xA4E70`）、FindClass（`0xA4E9C`）、ASN.1（`sub_CDCC8`）**全部未执行**。

调用来源：`lr = 0x14dc330`，超出 libnesec 模块范围（0x11D000），是 ART/JNI 注册回调直接调用。

**8s 后同一结构 `+0x101` 变为 1**，但该入口不再被调用 → 证书检查被“时序门控”错过。

---

## 3. 风险码实测

冷启动 30s，`sub_AFB34`（风险发射）实测 3 次：

| 顺序 | idx | 风险 | 调用者 lr |
|---|---|---|---|
| 1 | 4 | Hook | `0xB0A84`（runner `sub_B0990`） |
| 2 | 6 | 注入 | `0xB0A84` |
| 3 | 8 | Xposed | `0xB0A84` |

风险码来源：工作项结构 `+0x10`，runner 在 `0xB0A70: LDR W21,[X19,#0x10]` 取出后交给 `sub_AFB34`。

### 3.1 工作项构造者（wrapper）→ 风险码

实测命中：

| wrapper | 调用点 lr | `a2`（风险码） |
|---|---|---|
| `sub_D39D8` | `0x9DE80`（`sub_9D304` 内） | 1（来源/重打包） |
| `sub_D39D8` | `0x9DEF8`（`sub_9D304` 内） | **8（Xposed）** |
| `sub_D39D8` | `0x7F024` | -1（内部标记） |
| `sub_D55AC` | `0xB3CD8` | **6（注入）** |
| `sub_B2E30` | `0xB0A00` | runner 自身 |

即：Xposed 检测在 `sub_9D304` 内 `0x9DEF8` 处生成工作项；注入检测来自 `sub_B3CD8`。

风险 4（Hook）实测的生成点不在 `sub_9D304`：该段守卫 `+0xF7=0` 被跳过，风险 4 实际来自 `sub_919CC @ 0x91CA4`。

### 3.2 静态完整映射表（wrapper 调用点 → 风险码）

扫描 9 个 wrapper 的全部调用点，取调用前最近的 `MOV W2,#imm`（风险码）与 `LDRB [X19,#imm]`（守卫）：

| 调用点 | wrapper | 风险码 | 守卫偏移 | 风险 |
|---|---|---|---|---|
| `0x9DE7C` | D39D8 | 1 | `+0xB3` | 来源/重打包 |
| `0x9DBB8` | D55AC | 2 | `+0xE6` | 调试器 |
| `0x9DFB8` | D39D8 | 5 | `+0x102` | Root |
| `0x9DEDC` | D60A4 | 5 | - | Root |
| `0x9DEF4` | D39D8 | 8 | `+0xBE` | Xposed |
| `0x9DF7C` | D60A4 | 11 | `+0xCC` | 双开 |
| `0x9ED0C` | D85E4 | 13 | 容器比较（`[X19+0x270] != [X19+0x268]`） | ROM |
| `0x9ECA8` | D39D8 | 15 | `+0xF9` | 云手机 |
| `0x9DFA0` | D60A4 | 16 | `+0xF8` | 异常服务 |
| `0x9ECC8` | D85E4 | 20 | `+0xFE` | 抓包 |
| `0x9EC7C` | `sub_D7FA4`（直接发射） | 19 | `sub_9ED3C` 返回 bit0 | 虚拟定位 |
| `0x9EC90` | D55AC | 4 | `+0xF7` | Hook |
| `0x91CA4` | D60A4 | 4 | - | Hook（实测来源） |
| `0xB3CD4` | D55AC | 6 | - | 注入（实测来源） |
| `0xA3CDC` | D1F4C | ? | `+0xB5` | （`sub_A3848` 内，未执行） |
| `0xA4064` | D0E9C | ? | - | （`sub_A3848` 内，未执行） |

### 3.3 守卫字节实测

在 `0x9EC5C`（风险 4 前）下桩，读到 `X19 = 0x733ba21c58`，`+0xF7 = 0`。

注意：`sub_9D304` 的 `X19` **不是**全局配置单例 `0x733ba28ff8`，而是另一个“检测上下文”对象。因此 §1 的全局结构偏移与本节守卫偏移**不是同一张表**，不能直接交叉比对。

---

## 3.4 结论：实际发射的风险码

| 风险 | 是否发射 | 来源 |
|---|---|---|
| 4 Hook | 是（不稳定） | `sub_919CC @ 0x91CA4` |
| 6 注入 | 是 | `sub_B39F4 @ 0xB3CD4` |
| 8 Xposed | 是 | `sub_9D304 @ 0x9DEF4`（守卫 `+0xBE`） |
| 1/2/5/11/13/15/16/19/20 | 否 | 守卫位为 0 或检测未命中 |

### 3.5 风险 4（Hook）判定逻辑

`sub_919CC`（0x919CC，size 0x?，约 0x1E0 栈帧）：

1. `sub_8A094()` 取全局对象的 `+0x208/+0x210`（一个 vector 的 begin/end），遍历元素，元素大小 `0x18`。
2. 对每个元素取字符串，与 `"true"` 比较（`sub_4C15C`），并按空格切分（`asc_10DB9 = " "`）。
3. 分词结果与关键词表 `qword_E3BC8`（3 个指针，24 字节）逐项比较（`sub_DB250`）。
4. 命中 → `W21 = 1`（`0x91AE4`）→ 写 `var_6B`（`0x91B24`）。
5. `0x91C60: CBZ var_6B` → 为 1 时走 `0x91C64`：从栈上 `var_170` 复制 0x106 字节消息 → 入队风险 4（`sub_D60A4`，W2=4）。

关键词表运行时内容（模块内偏移 `0x12009` 起）：

```
"libart.so"  "android_link_namespaces"  ".*liblog\.so$"
```

（第一项已实测确认；后两项按字符串池相邻顺序推断。）

语义：在系统字符串列表（很可能是 `/proc/self/maps` 或进程属性列表）中查找非预期的 `libart.so` / 链接器符号 / `liblog` 引用，命中即判定为 Hook/注入。消息体是命中的那条文本（截断 0x106 字节）。

实测注意：风险 4 的触发不稳定——19 次注入里约半数启动会发，取决于注入时机；其余时候该分支未命中，但风险 6/8 稳定发射。

### 3.6 风险 6（注入）判定逻辑

`sub_B39F4` 末尾（`0xB3C90..0xB3CD4`）：

```
X1 = "__dl_dlopen"
BL qword_D4610          ; 运行时解析 linker 内部符号
TBZ W0,#0 → 跳过注册
  sub_68260(sub_B398C, qword_EE0E0)   ; 注册回调
sub_B1708(SP+var_490)   ; 清理栈上结构（非检测）
X0 = sub_B36C8          ; 消息来源
W2 = 6                  ; 风险码 6
BL sub_D55AC            ; 入队
```

要点：

- 检测锚点是 Android linker 的内部符号 `__dl_dlopen`（静态字符串 `0x120CB`）。
- `qword_D4610` 是函数指针（运行时解析），用它做符号/地址校验。
- 进入 `0xB3CD4` 后**无条件**入队风险 6，触发条件在本函数上游（`0xB39F4` 入口到该段的判定）。

风险 6 在实测中每次 Frida 注入后都稳定出现，是三条生效检测里最可靠的一条。

---

## 4. 检测函数实际执行面

对 437 个检测类函数（`risk_emitter_support`/`verdict_support`/`hook_check_support`/`xposed_probe_support`/`root_check_support`/`inject_check_support`/…）下桩，20s 内 **72 个命中**，明细：`artifacts/nesec_flags/detect_hits.csv`。

注意：高频调用（`0xD3EA8` 71 万次、`0xD40C0` 17 万次）基本是字符串/内存工具被低置信分类误标成 root/inject 检测，不能当作检测逻辑。低频且成组出现的才是真实检测点：

| 地址 | 分类 | 次数 |
|---|---|---|
| `0xD9620` | hook_check | 13 |
| `0xDA6EC` | xposed_caller | 12 |
| `0xABC04` | verdict | 8 |
| `0xD8A3C` | risk_emitter | 2 |
| `0xD6A1C` | risk_emitter | 1 |
| `0xD737C` | fd_task_scan | 1 |

---

## 5. `sub_A3848` / `sub_A460C` 未执行

- `sub_A3848`：18 个内部块 + 入口，全部 0 命中。
- `sub_A460C`：5 个内部块 + 入口，全部 0 命中。

这两个函数是另一个（未接线的）检测汇总入口，不是本 app 启动路径的一部分。这与风险 17（屏幕共享）未接线、证书链被门控的情况一致：**libnesec 携带的能力大于实际接线的能力**。

---

## 6. 结论

1. libnesec 的实际生效面比函数清单小得多：冷启动真正执行的检测函数 72 个，其中大部分是工具函数。
2. 实测生效的检测：Frida/Hook（风险 4）、注入（6）、Xposed（8），其中 6/8 已定位到具体构造点。
3. 证书链因 `+0x101=0` 时序门控 + 目标类缺失，双重不可达。
4. `sub_A3848`/`sub_A460C` 整套门控代码未被调用，其十几个标志位对当前 app 行为无影响。

---

## 7. 复现

```bash
# 块级命中
frida -U -f com.example.sampleb -l /tmp/wm_tools/blk_probe.js -q -t 24 --runtime=v8
# 门控开关
frida -U -f com.example.sampleb -l /tmp/wm_tools/a4cdc_flags.js -q -t 25 --runtime=v8
# 风险码与 wrapper
frida -U -f com.example.sampleb -l /tmp/wm_tools/wrapper_trace.js -q -t 28 --runtime=v8
# 检测函数命中面
frida -U -f com.example.sampleb -l /tmp/wm_tools/detect_probe.js -q -t 26 --runtime=v8
```
