> **来源**：`<external-research-dir>/sampleb/libnesec_函数分类汇总.md`。
> 证据级别映射：观测→V，代码→S，推断→I，未知→U。分类 CSV 属外部研究产物，不入本仓库。
> 用途：判断检测面与工具函数占比；不把 `*_support` 分类当作专属功能证据（见 `docs/设计文档.md` §17.9）。

---

# libnesec.so 全量函数分类

- 日期：2026-11-21
- 样本：libnesec.so（8ff576e1…），4,226 个函数
- CSV：`artifacts/nesec_full_decomp/function_classification.csv`

## 方法

1. **关键函数锚点**（73 个，高置信）：来自加载器/检测/发射/退出/字符串/证书等已分析函数。
2. **调用图可达性**：从关键函数向前 BFS（深度 3）标 `<检测名>_support`；向前向 BFS（深度 2）标 `<检测名>_caller`。
3. **公共工具**：被 ≥4 个关键簇可达 → `common_util`；入度 ≥20 且 ≤0x400 → `runtime_common`。
4. **启发式**：STL/RTTI、ASN.1、cJSON、pthread、文件/进程、网络、内存/字符串、数学、syscall。
5. **兜底**：≤0x30 的叶子 → `leaf_util`；无证据 → `unclassified`；导入 thunk → `missing`。

## 置信度

| 置信度 | 数量 | 说明 |
|--------|------|------|
| high | 73 | 关键函数锚点，角色明确 |
| medium | 2000 | 调用图可达/高入度，角色较可信 |
| low | 2153 | 启发式/叶子/未分类 |

## 分类统计（Top）

| 分类 | 数量 |
|------|------|
| leaf_util | 1303 |
| common_util | 879 |
| unclassified | 609 |
| inject_check_support | 146 |
| cert_asn1_support | 119 |
| probe_caller_support | 101 |
| string_util_caller | 89 |
| runtime_common | 82 |
| vmos_check_support | 80 |
| verdict_support | 79 |
| risk_emitter_support | 56 |
| missing | 54 |
| hook_check_support | 41 |
| detect | 38 |
| shell_init_support | 38 |
| workitem_callback_support | 37 |
| jni_bridge_support | 32 |
| root_check_support | 31 |
| jni_emit_wrapper_support | 29 |
| large_unknown | 28 |
| xposed_probe_support | 28 |
| proxy_vpn_check_support | 27 |
| mock_location_check_support | 25 |
| dex_check_support | 20 |
| debug_check_support | 19 |
| root_cert_check_support | 19 |
| emitter | 17 |
| cpp_runtime | 15 |
| fd_task_scan_support | 14 |
| instrumentation_proxy_support | 14 |
| maps_scanner_caller | 13 |
| jni_emit_wrapper_caller | 12 |
| hook_marker_match_support | 11 |
| loader | 11 |
| workitem_wrapper_support | 11 |
| maps_scanner_support | 10 |
| xposed_caller_support | 9 |
| workitem_runner_support | 8 |
| mem_scan_support | 6 |
| magisk_check_support | 6 |

## 关键函数（high confidence）

### loader（11）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x7c458 | sub_7C458 | jni_onload_resolver |
| 0x8040c | sub_8040C | instrumentation_proxy |
| 0x861d8 | sub_861D8 | jni_bridge |
| 0xa05ac | sub_A05AC | jni_bridge |
| 0xa460c | sub_A460C | jni_bridge |
| 0xf5504 | sub_F5504 | shell_init |
| 0xf55b4 | sub_F55B4 | shell_init |
| 0xf5d08 | sub_F5D08 | shell_init |
| 0xf6548 | sub_F6548 | shell_init |
| 0xf72c4 | sub_F72C4 | shell_init |
| 0xfb398 | sub_FB398 | shell_init |

### detect（38）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x6c26c | sub_6C26C | hook_check |
| 0x6c644 | sub_6C644 | hook_strings_init |
| 0x8aaac | sub_8AAAC | debug_check |
| 0x8ad50 | sub_8AD50 | mem_scan |
| 0x8be38 | sub_8BE38 | debug_check |
| 0x8d9b8 | sub_8D9B8 | dex_check |
| 0x8f544 | sub_8F544 | dex2oat_check |
| 0x8fa84 | sub_8FA84 | fd_task_scan |
| 0x90250 | sub_90250 | hook_check |
| 0x91338 | sub_91338 | hook_check |
| 0x92948 | sub_92948 | sdk_branch |
| 0x96e58 | sub_96E58 | proxy_vpn_check |
| 0x97b88 | sub_97B88 | root_verdict |
| 0x97bdc | sub_97BDC | root_check |
| 0x9cb3c | sub_9CB3C | hook_check |
| 0x9ff30 | sub_9FF30 | probe_caller |
| 0xa13ec | sub_A13EC | inject_check |
| 0xa3848 | sub_A3848 | verdict |
| 0xa413c | sub_A413C | mock_location_check |
| 0xa4cdc | sub_A4CDC | root_cert_check |
| 0xa706c | sub_A706C | maps_scanner |
| 0xaa61c | sub_AA61C | xposed_caller |
| 0xaa7b4 | sub_AA7B4 | xposed_probe |
| 0xade74 | sub_ADE74 | maps_scanner |
| 0xae120 | sub_AE120 | prop_check |
| 0xb10d4 | sub_B10D4 | maps_scanner |
| 0xb1c24 | sub_B1C24 | emulator_check |
| 0xb342c | sub_B342C | hook_marker_match |
| 0xb39f4 | sub_B39F4 | status_seccomp_check |
| 0xc9724 | sub_C9724 | package_check |
| 0xca334 | sub_CA334 | vmos_check |
| 0xcb5e0 | sub_CB5E0 | magisk_check |
| 0xcc4a0 | sub_CC4A0 | root_check |
| 0xcdcc8 | sub_CDCC8 | cert_asn1 |
| 0xd04d0 | sub_D04D0 | log_parse |
| 0xda560 | sub_DA560 | maps_scanner |
| 0xfb87c | sub_FB87C | ldpreload_check |
| 0xfde30 | sub_FDE30 | maps_scanner |

### emitter（17）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x69e94 | sub_69E94 | jni_emit_wrapper |
| 0x998f4 | sub_998F4 | workitem_callback |
| 0x9bc2c | sub_9BC2C | workitem_wrapper |
| 0x9d304 | sub_9D304 | risk_emitter |
| 0xafb34 | sub_AFB34 | risk_emitter_block |
| 0xb00b4 | sub_B00B4 | workitem_runner |
| 0xb0990 | sub_B0990 | workitem_runner |
| 0xb0ae0 | sub_B0AE0 | workitem_builder |
| 0xb2908 | sub_B2908 | workitem_callback |
| 0xb2e30 | sub_B2E30 | workitem_wrapper |
| 0xcb9b0 | sub_CB9B0 | workitem_callback |
| 0xcc2b4 | sub_CC2B4 | workitem_wrapper |
| 0xd0e9c | sub_D0E9C | workitem_wrapper |
| 0xd39d8 | sub_D39D8 | workitem_wrapper |
| 0xd55ac | sub_D55AC | workitem_wrapper |
| 0xd60a4 | sub_D60A4 | workitem_wrapper |
| 0xd85e4 | sub_D85E4 | workitem_wrapper |

### exit（2）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x2d610 | sub_2D610 | exit_group_stub |
| 0xd1f4c | sub_D1F4C | exit_path |

### syscall（3）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x2d598 | sub_2D598 | syscall_wrapper |
| 0x2d5c8 | sub_2D5C8 | syscall_wrapper |
| 0x2d628 | sub_2D628 | syscall_wrapper |

### util（2）

| 地址 | 名称 | 角色 |
|------|------|------|
| 0x6b7a8 | sub_6B7A8 | string_util |
| 0xb1bec | sub_B1BEC | string_decrypt |

## 支持簇（Top 20）

| 分类 | 数量 |
|------|------|
| inject_check_support | 146 |
| cert_asn1_support | 119 |
| probe_caller_support | 101 |
| string_util_caller | 89 |
| vmos_check_support | 80 |
| verdict_support | 79 |
| risk_emitter_support | 56 |
| hook_check_support | 41 |
| shell_init_support | 38 |
| workitem_callback_support | 37 |
| jni_bridge_support | 32 |
| root_check_support | 31 |
| jni_emit_wrapper_support | 29 |
| xposed_probe_support | 28 |
| proxy_vpn_check_support | 27 |
| mock_location_check_support | 25 |
| dex_check_support | 20 |
| debug_check_support | 19 |
| root_cert_check_support | 19 |
| fd_task_scan_support | 14 |

## 剩余桶说明

- `leaf_util`（1,303）：≤0x30 的小函数，多为 getter/setter/内联辅助。
- `common_util`（879）：被 ≥4 个关键簇可达，通用容器/内存/字符串辅助。
- `runtime_common`（82）：入度 ≥20，C++ 运行时/分配器/异常。
- `unclassified`（609）：无字符串/导入/调用图证据；其中 557 在解密段，多为 0x31–0x400 的运行时/工具函数。
- `missing`（54）：导入 thunk。
- `large_unknown`（28）：>0x400 且无证据的大函数。

> 注意：`*_support` 表示“从该检测函数可达”，不等于该函数只服务于该检测；`unclassified` 不等于不存在功能，只是当前证据不足。
