# 2026-11-21 P2：自研 loader 的 TLS relocation

## 范围

为自研 ELF loader 增加动态 TLS：注册 `PT_TLS`、处理 DTPMOD/DTPREL、AArch64
TLSDESC 描述符，并把 `__tls_get_addr` 绑定到自管 TLS 运行时。静态 TLS 类
（TPREL/GOTTPOFF/TLSGD/TLSLD）仍按失败处理并回退平台 linker。

## 实现

| 位置 | 内容 |
|---|---|
| `tls_runtime.h/.cpp` | 模块注册、每线程 TLS 块、`__tls_get_addr`、AArch64 TLSDESC resolver；pthread key 负责线程块释放 |
| `elf_loader.cpp` | 解析 `PT_TLS` 并注册模块；处理 `R_*_TLS_DTPMOD`、`R_*_TLS_DTPREL`、`R_AARCH64_TLSDESC`；未定义 TLS 符号失败回退 |
| `resolveSymbol` | 将未定义的 `__tls_get_addr` 直接绑定到 `fm_tls_get_addr_entry`，不依赖 bionic 是否导出 |
| `file_hooks.cpp` | 对平台已加载库仍 hook `__tls_get_addr`；自研镜像优先走本地 TLS 运行时 |
| TLS 失败策略 | `TPREL`、`GOTTPOFF`、`TLSGD`、`TLSLD`、跨模块未定义 TLS 符号 → loader 返回失败，平台 fallback |

### 语义

- `DTPMOD`：写入自管模块 ID（`0x40000000 + slot`）。
- `DTPREL`：写入 TLS 符号的块内偏移 + addend。
- `TLSDESC`：写入 `{resolver, FmTlsIndex*}`；resolver 返回 `block - thread_pointer`。
- 每线程首次访问分配对齐块，复制 `.tdata` 并清零 `.tbss`。

## 验证（宿主，实际 loader 代码）

x86_64 Android TLS 库（`-fno-emulated-tls -ftls-model=global-dynamic`，
`R_X86_64_DTPMOD64/DTPOFF64`），Rosetta x86_64 进程：

```text
[FMElf] loaded libtls.so base=... size=49152
tls=1,2 other=1
```

AArch64 Android TLS 库（`R_AARCH64_TLSDESC`），macOS arm64 / `PAGE_SIZE=16384`：

```text
[FMElf] loaded libtls.so base=... size=49152
tls=1,2 other=1
```

`other=1` 证明新线程拿到独立 TLS 块；`1,2` 证明同线程状态递增。

## 限制

1. `-fno-emulated-tls` 的 demo App 在 NDK 链接阶段拿不到 bionic 的
   `__tls_get_addr`（bionic 不作为可链接符号导出），因此未做 App 内置 TLS 的设备探针；
   预编译的 native TLS 业务库可由自研 loader 的本地绑定处理。
2. 仅支持动态 TLS（DTPMOD/DTPREL/TLSDESC）；`TPREL`/`GOTTPOFF`/`TLSGD`/`TLSLD`
   以及跨模块未定义 TLS 符号仍回退平台 linker。
3. TLS 块是堆分配、以线程指针差值寻址，不等同于 bionic 的静态 TLS 布局；
   极端代码若直接比较/推算 TP 偏移，行为可能不同。
4. 模块上限 64；`dlclose`/`close` 只释放 loader 侧的索引，运行时模块元数据保留。
5. 设备矩阵尚未覆盖；当前证据为宿主 16 KB 页与 x86_64 Rosetta 执行。
