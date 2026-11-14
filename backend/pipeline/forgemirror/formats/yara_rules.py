"""YARA-backed rule compilation and APK scanning.

The product rules below are independently written demo rules for semantics
and regression testing, not the research-side nine-rule corpus. Runtime shell
integration still uses PKR1 string rules; this module is the host-side engine
used to validate rule semantics and scan artifacts.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yara = None


class YaraUnavailable(Exception):
    pass


class YaraRuleError(Exception):
    pass


PRODUCT_RULES = r"""
rule fm_dynamic_instrumentation
{
    meta:
        id = "fm_dynamic_instrumentation"
        severity = "high"
    strings:
        $a1 = "frida-server" ascii wide
        $a2 = "frida-agent" ascii wide
        $a3 = "gum-js-loop" ascii
        $a4 = "linjector" ascii
    condition:
        any of them
}

rule fm_xposed_framework
{
    meta:
        id = "fm_xposed_framework"
        severity = "high"
    strings:
        $a1 = "XposedBridge" ascii wide
        $a2 = "de.robv.android.xposed" ascii
        $a3 = "LSPosed" ascii wide
        $a4 = "EdXposed" ascii wide
    condition:
        any of them
}

rule fm_root_shell
{
    meta:
        id = "fm_root_shell"
        severity = "medium"
    strings:
        $a1 = "/system/bin/su" ascii
        $a2 = "/system/xbin/su" ascii
        $a3 = "Superuser.apk" ascii wide
        $a4 = "magisk" ascii wide
    condition:
        any of them
}

rule fm_debugger_attach
{
    meta:
        id = "fm_debugger_attach"
        severity = "medium"
    strings:
        $a1 = "ptrace" ascii
        $a2 = "TracerPid" ascii
        $a3 = "waitForDebugger" ascii
    condition:
        2 of them
}

rule fm_emulator_artifact
{
    meta:
        id = "fm_emulator_artifact"
        severity = "low"
    strings:
        $a1 = "goldfish" ascii
        $a2 = "ranchu" ascii
        $a3 = "qemu_pipe" ascii
        $a4 = "ro.kernel.qemu" ascii
    condition:
        2 of them
}

rule fm_hook_framework
{
    meta:
        id = "fm_hook_framework"
        severity = "high"
    strings:
        $a1 = "Dobby" ascii wide
        $a2 = "ShadowHook" ascii wide
        $a3 = "bhook" ascii
        $a4 = "inline hook" ascii wide
    condition:
        any of them
}

rule fm_dex_memory_loading
{
    meta:
        id = "fm_dex_memory_loading"
        severity = "medium"
    strings:
        $a1 = "InMemoryDexClassLoader" ascii
        $a2 = "makeInMemoryDexElements" ascii
        $a3 = "DexPathList" ascii
    condition:
        2 of them
}

rule fm_signature_tamper
{
    meta:
        id = "fm_signature_tamper"
        severity = "medium"
    strings:
        $a1 = "GET_SIGNATURES" ascii
        $a2 = "getPackageInfo" ascii
        $a3 = "signatures" ascii
    condition:
        2 of them
}

rule fm_network_interception
{
    meta:
        id = "fm_network_interception"
        severity = "low"
    strings:
        $a1 = "tcpdump" ascii wide
        $a2 = "mitmproxy" ascii wide
        $a3 = "Burp Suite" ascii wide
        $a4 = "proxyDroid" ascii wide
    condition:
        any of them
}

rule fm_unpack_framework
{
    meta:
        id = "fm_unpack_framework"
        severity = "high"
    strings:
        $a1 = "youpk" ascii wide nocase
        $a2 = "fupk3" ascii wide nocase
        $a3 = "yarfahook" ascii wide nocase
        $a4 = "dumpArtMethod" ascii
        $a5 = "dumpdexfilebyArtMethod" ascii
        $a6 = "shouldUnpack" ascii
        $a7 = "myfartInvoke" ascii
    condition:
        any of them
}
"""

# Demo-only rule used by the protected harness to prove the runtime engine is
# live. It is not part of the product rule set.
DEMO_RULE = r"""
rule fm_demo_jni
{
    meta:
        id = "fm_demo_jni"
        severity = "low"
    strings:
        $a1 = "Java_dev_forgemirror_demo_MainActivity_stringFromJNI" ascii
    condition:
        $a1
}
"""

RUNTIME_RULES = PRODUCT_RULES + DEMO_RULE


@dataclass
class YaraMatch:
    rule: str
    entry: str | None
    sha256: str | None = None


def ensure_available() -> None:
    if yara is None:
        raise YaraUnavailable(
            "yara-python is not installed; install the 'yara' extra"
        )


def compile_rules(source: str = PRODUCT_RULES):
    ensure_available()
    try:
        return yara.compile(source=source)
    except yara.SyntaxError as error:  # type: ignore[attr-defined]
        raise YaraRuleError(str(error)) from error


def scan_bytes(data: bytes, rules) -> list[str]:
    ensure_available()
    return sorted(match.rule for match in rules.match(data=data))


def scan_file(path: Path, rules) -> list[str]:
    ensure_available()
    try:
        return sorted(match.rule for match in rules.match(str(path)))
    except yara.Error as error:  # type: ignore[attr-defined]
        raise YaraRuleError(str(error)) from error


def scan_apk(apk: Path, rules=None, source: str = PRODUCT_RULES) -> list[YaraMatch]:
    engine = rules if rules is not None else compile_rules(source)
    matches: list[YaraMatch] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if not info.filename.startswith("lib/") or not info.filename.endswith(".so"):
                continue
            data = archive.read(info.filename)
            digest = hashlib.sha256(data).hexdigest()
            for rule in scan_bytes(data, engine):
                matches.append(YaraMatch(rule=rule, entry=info.filename, sha256=digest))
    return matches
