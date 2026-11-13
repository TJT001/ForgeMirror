# 2026-11-13 P1：DT_INIT 自解密 + LZSS

## 范围

`libshield_boot.so`、`libshield_hook.so`、`libshield_yara.so` 加载时不再以明文
`.text` 落盘：`.text` 先 LZSS 压缩，再用 32 字节随机 key 逐字节 XOR，追加到文件
尾部；对应的最后 `PT_LOAD` 扩展 `p_filesz/p_memsz` 把 payload 映射进内存。
`DT_INIT` 指向 `.fm_selfdecrypt` 中的 stub，由它解密 `.text`、刷新 I-cache，再把
页面权限从 RWX 收回 RX。

## 实现

| 模块 | 内容 |
|---|---|
| `formats/selfdecrypt.py` | `lzss_compress/lzss_decompress`；`add_dt_init_lzss` 压缩 `.text`、异或加密、追加 payload、扩展最后 `PT_LOAD`、写 `.fm_meta`、把 `.text` 填 `0xA5` |
| `selfdecrypt.c` | `.fm_meta`（magic/target/payload/dynamic vaddr + key）；`fm_selfdecrypt_init` 计算 load base、mprotect RWX、LZSS 解压、I-cache flush、mprotect RX；stub 与 `fm_read/fm_lzss/fm_clear_cache` 全部放在 `.fm_selfdecrypt` |
| `CMakeLists.txt` | boot/hook/yara 链 `-Wl,-init=fm_selfdecrypt_init -Wl,-u,fm_selfdecrypt_init` |
| `protect.py` | 对三个库依次执行 DT_INIT 变换，再执行双 `PT_DYNAMIC` 诱饵与 section 名表破坏；`--self-decrypt-text/--no-self-decrypt-text` |
| `test_selfdecrypt.py` | 合成 ELF64：验证解压回原 `.text`、`.text` 填充、section 头迁移、BSS 映射区全零、`PT_LOAD` 扩展 |

I-cache 刷新不调用编译器运行时：

- ARM64：`mrs ctr_el0` 取行大小，`dc cvau` + `dsb ish` + `ic ivau` + `dsb ish/isb`；
- ARM32：内联 `svc #0`，`r7 = 0x0f0002 (__ARM_NR_cacheflush)`，临时保存 `r7`；
- x86/x86_64：缓存一致，no-op。

## 关键修复：扩展 `p_filesz` 会把 `.bss` 变成文件映射

最后一个 `PT_LOAD` 的 `p_memsz` 覆盖 `.bss`，但 `p_filesz` 只到 `.data` 末尾。
最初直接把 `p_filesz` 扩展到 payload，内核因此把 `.bss` 所在页改为文件映射：
该文件区间里原有的 `.comment`、`.shstrtab`、section header table 字节被映射进
`gLock`、`gDataDir` 等 BSS 变量，`std::mutex` 初始状态变成 section 字节，表现为
主线程 100% CPU 自旋（`nativeConfigure` 取锁不返回）。开启 section 名表破坏时
这些字节是 `0xA5`，还能在 JNI 返回值里直接观察到 `0xa5`。

修复方式：在 `add_dt_init_lzss` 中

1. 把 `shstrtab` 与 section header table 搬到 payload 之后，并回填 `e_shoff` 与
   shstrtab 的 `sh_offset`；
2. 将 `[原 p_filesz 末尾, payload 起点)` 全部清零，保证所有映射进 `.bss` 的文件
   字节为 0；
3. 再写入 payload 并扩展 `p_filesz/p_memsz`。

## 验证

构建日志（`protect` 输出的应用到的大小）：

```text
lib/arm64-v8a/libshield_boot.so: 2164B -> 1257B
lib/arm64-v8a/libshield_hook.so: 261940B -> 122758B
lib/arm64-v8a/libshield_yara.so: 598228B -> 263534B
```

设备（Pixel 5 / API 30，完整组合：DT_INIT LZSS + 双 PT_DYNAMIC + section 名表破坏）：

```text
FMDecrypt: init base=0x70d0a58000 target=0x70d0a58e5c size=2164 payload=0x70d0a63000 len=1257
FMDecrypt: lzss ok=1
FMDecrypt: hash=0776cb458365d087
FMDecrypt: stub done
FMDecrypt: init base=0x70d0909000 target=0x70d093b380 size=261940 payload=0x70d0991000 len=122758
FMDecrypt: lzss ok=1
FMDecrypt: hash=ec7c1d741bbaed9b
FMDecrypt: stub done
ShieldRuntime: native file hooks status=0
FMDecrypt: init base=0x70792c3000 target=0x70792fba30 size=598228 payload=0x70793ae000 len=263534
FMDecrypt: lzss ok=1
FMDecrypt: hash=93bf0750a9b78db9
FMDecrypt: stub done
ShieldRuntime: dex loaded count=7 decryptMs=273
ShieldRuntime: encrypted core opened fd=59
ShieldRuntime: bootstrap ok state=4
ShieldRuntime: rule scan done matches=4 ms=68
```

stub 内 FNV-1a hash 与离线对原始 `.text` 计算的值一致，证明还原字节级一致。
透明 I/O UI 回读仍全部为 0：

```text
probe writeErr=0 readErr=0 mmapErr=0 syscallErr=0
textErr=0 native=T2XYZ6 java=T2XYZ6 mmapWriteErr=0
javaMmap=M2XYZ6 periodic=P2XYZ6
readback prefs=true counter=1 file=true append=true ra=true mmap=true
```

Python 侧 63 项测试通过（含新增 `test_selfdecrypt.py`）。

## 限制

1. 只处理 `libshield_boot.so`、`libshield_hook.so`、`libshield_yara.so`；`libshield_core.so` 仍走 FD 加密加载。
2. key 与 stub 同文件，`fm_meta` 静态可读；这是防静态反编译的壳层，不是密钥保密方案。
3. payload 通过扩展最后 `PT_LOAD` 映射，`/proc/self/maps` 中该段可见为 RWX 窗口（stub 完成后收回 RX）。
4. ARM32 内联 `svc` 路径已编译通过，但当前设备矩阵只实测了 ARM64。
5. 未做真正的内存 ELF loader；`.text` 解密后仍在进程内明文可读。
