# 2026-11-13 P1：双 PT_DYNAMIC 诱饵

## 实现

对注入 APK 的明文 shield so（`libshield_boot.so`、`libshield_hook.so`、
`libshield_yara.so`、`libshadowhook.so`）做 ELF 后处理：

1. 读取真实 `PT_DYNAMIC`（`p_offset`/`p_vaddr`/`p_filesz`）与动态项；
2. 在文件末尾追加诱饵表，只保留 `DT_NEEDED`、`DT_SONAME`、`DT_STRTAB`、`DT_STRSZ`、`DT_NULL`；
3. 把 `PT_DYNAMIC.p_offset` 指向诱饵，**保留 `p_vaddr` 指向真实表**；
4. 把 `.dynamic` section 的 `sh_offset` 指向诱饵，`sh_size` 保留原 `p_filesz`；
5. 保留 section header table 与 `e_shstrndx`，避免 linker 校验失败；
6. 诱饵后按 `p_filesz` 补零，保证 `p_offset + p_filesz` 不越界；
7. 保留 `e_shstrndx` 索引合法，但把 section header string table 内容填成 `0xA5`
   （非 NUL 结尾），使静态工具无法解析节名；
8. `--keep-section-names` 可关闭第 7 步，`--no-decoy-dynamic` 可整体关闭。

支持 ELF64 与 ELF32。

## 为什么保留 section size

实测 linker 会校验：

```text
.dynamic section has invalid size: 0x80, expected to match PT_DYNAMIC filesz: 0x1a0
```

因此只改 `sh_offset`，`sh_size` 保持原值；静态工具从诱饵表头读到 `DT_NULL` 即停止。

## 验证

### 静态工具

对 APK 内 `lib/arm64-v8a/libshield_boot.so`：

```text
Dynamic section at offset 0x1eb0 contains 8 entries:
  NEEDED liblog.so / libdl.so / libm.so / libc.so
  SONAME libshield_boot.so
  STRTAB 0x4e0
  STRSZ 433
  NULL
```

真实表仍在原位置，`PT_DYNAMIC.p_vaddr` 未变：

```text
DYNAMIC 0x001eb0 0x0000000000005568 ... 0x1a0
```

`libshield_hook.so` / `libshield_yara.so` 同样只显示 NEEDED/SONAME/STRTAB/STRSZ。

### 设备

```text
ShieldRuntime: native file hooks status=0
ShieldRules: YARA rules compiled
ShieldRuntime: encrypted core opened fd=59
ShieldRuntime: bootstrap ok state=4
```

即 linker 按 `p_vaddr` 读真实动态表，boot/hook/shadowhook/yara 全部正常加载。

section 名表破坏后：

```text
llvm-readelf -S libshield_boot.so
warning: SHT_STRTAB string table section [index 21] is non-null terminated
[ 0] <no-strings> ...
[ 1] <no-strings> ...
```

`llvm-readelf -d` 仍从 `.dynamic` section（offset 已指向诱饵）读出上面的 8 项；
`--dyn-syms` 会警告无法取得 SHT_DYNSYM 节名，但符号内容仍可通过 section type 访问。

### 测试

```text
test_elf.py: ELF64 诱饵表/真实表/NEEDED 计数
Python pipeline 62 项
Shield JVM 18 项
Go build/vet 通过
```

## 限制

1. 只处理 shield 自有明文 so；core 已是加密 asset，业务 .so 未处理。
2. section header table 与 `e_shstrndx` 索引仍合法（linker 会校验）；名称内容已破坏，
   但按 section type 扫描 `.dynsym`/`.rela` 的分析器仍能还原符号内容。
3. 参考壳还配合 `DT_INIT` 自解密/LZSS；本实现只做双表与名表破坏。
4. 未实现 `DT_INIT` 自解密、LZSS、I-cache 刷新、内联 syscall 桩。
5. 诱饵表追加在文件末尾，文件大小增加 `p_filesz` 级别的零填充；不影响 zipalign/签名。
6. x86/x86_64 的 ELF32/64 逻辑已支持，但 x86 原生 hook 仍不存在。
