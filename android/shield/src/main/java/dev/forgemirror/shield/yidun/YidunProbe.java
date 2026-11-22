package dev.forgemirror.shield.yidun;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;
import android.os.UserManager;
import android.provider.Settings;
import android.system.Os;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Environment probes carried over from the NetEase Yidun {@code libnesec.so}
 * sample. Rule IDs are prefixed with {@code yidun_} so events can be attributed
 * to this source. The probe never exits, kills, or blocks; it only returns
 * findings for the shared event and response pipeline.
 *
 * <p>Only the detection surface is absorbed. Yidun's {@code exit_group}
 * response, 7-bit string cipher, and unreachable certificate chain are
 * deliberately not reproduced. See {@code docs/设计文档.md} §17.9.
 */
public final class YidunProbe {
    public static final String RULE_ROOT = "yidun_root";
    public static final String RULE_MOUNT = "yidun_mount";
    public static final String RULE_DEBUG = "yidun_debug";
    public static final String RULE_HOOK = "yidun_hook";
    public static final String RULE_XPOSED = "yidun_xposed";
    public static final String RULE_INJECTION = "yidun_injection";
    public static final String RULE_EMULATOR = "yidun_emulator";
    public static final String RULE_LD_PRELOAD = "yidun_ld_preload";
    public static final String RULE_DEX = "yidun_dex";
    public static final String RULE_USB_DEBUG = "yidun_usb_debug";
    public static final String RULE_VPN = "yidun_vpn";
    public static final String RULE_MOCK_LOCATION = "yidun_mock_location";
    public static final String RULE_ROM = "yidun_rom";
    public static final String RULE_PROXY = "env_proxy";
    public static final String RULE_PACKET_CAPTURE = "env_packet_capture";
    public static final String RULE_CLONE = "env_clone";
    public static final String RULE_AUTOTAP = "env_autotap";
    public static final String RULE_SCREEN_SHARE = "env_screen_share";

    private static final String TAG = "YidunProbe";
    private static final long MAX_PROC_BYTES = 8L << 20;
    private static final int MAX_FDS = 256;
    private static final int MAX_TASKS = 512;
    private static final int MAX_PACKAGES = 128;
    private static final int MAX_MAPS_FILES = 64;
    private static final int MAX_DEX_FILES = 64;

    private static final String[] MOCK_LOCATION_PACKAGES = {
            "com.lexa.fakegps",
            "com.incorporateapps.fakegps",
            "com.rosteam.gpsemulator",
            "ru.gavrikov.mocklocations",
            "com.fly.gps",
            "com.blogspot.newapphorizons.fakegps",
            "com.evezzon.gpsemulator",
            "com.gpsemulator",
            "com.mock.location",
            "com.fakegps.mock",
    };

    private static final String[] CAPTURE_CA_MARKERS = {
            "mitmproxy", "charles", "fiddler", "burp", "portswigger",
            "proxyman", "httptoolkit", "http toolkit", "owasp zap",
            "zap proxy", "wireshark",
    };

    private static final String[] CLONE_PACKAGES = {
            "com.lbe.parallel",
            "com.excelliance.dualaid",
            "com.polestar.clone",
            "com.polestar.domultiple",
            "com.lody.virtual",
            "io.va.exposed",
            "com.vmos.pro",
            "com.vmos.lite",
            "com.parallel.space",
            "com.dual.space",
            "com.clone.app",
            "com.svm.parallel",
    };

    private static final String[] CAPTURE_PACKAGES = {
            "com.pcapdroid",
            "com.emanuelef.remote_capture",
            "com.minhui.networkcapture",
            "com.tacapture",
            "com.packet.capture",
            "com.wireshark",
    };

    private static final String[] SCREEN_SHARE_PACKAGES = {
            "com.hecorat.screenrecorder.free",
            "com.duapps.recorder",
            "com.recorder.screen",
            "com.mobizen",
            "com.az.screen.recorder",
            "com.kimcy929.screenrecorder",
            "com.orpheusdroid.screenrecorder",
            "com.izzyondroid.screenrecorder",
    };

    private static final String[] AUTOMATION_PACKAGES = {
            "org.autojs.autojs",
            "org.autojs.autoxjs",
            "com.arlosoft.macrodroid",
            "net.dinglisch.android.taskerm",
            "com.llamalab.automate",
            "com.hamibot.hamibot",
            "com.touchsprite.android",
            "com.cyjh.mobileanjian",
            "com.easy.auto.click",
            "com.auto.clicker",
            "com.superauto.clicker",
            "com.github.uiautomator",
    };

    public static final class Finding {
        public final String ruleId;
        public final String kind;
        public final String evidence;
        public final double confidence;

        Finding(String ruleId, String kind, String evidence, double confidence) {
            this.ruleId = ruleId;
            this.kind = kind;
            this.evidence = evidence;
            this.confidence = confidence;
        }
    }

    private final YidunSignatures signatures;

    public YidunProbe(YidunSignatures signatures) {
        this.signatures = signatures == null ? YidunSignatures.empty() : signatures;
    }

    public List<Finding> scan(Context context) {
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        scanRoot(findings, seen);
        scanMounts(findings, seen);
        scanTaskStatus(findings, seen);
        scanSelfStatus(findings, seen);
        scanEmulatorPaths(findings, seen);
        scanEmulatorBuild(findings, seen);
        scanEmulatorProperties(findings, seen);
        String maps = readText("/proc/self/maps");
        String[] mapsLines = maps.isEmpty() ? new String[0] : maps.split("\n");
        scanMaps(mapsLines, findings, seen);
        scanDex2oat(mapsLines, findings, seen);
        scanHookClasses(findings, seen);
        scanHookServices(findings, seen);
        scanFileDescriptors(findings, seen);
        scanLdPreload(findings, seen);
        scanCloudPhonePackages(context, findings, seen);
        scanCloudServices(findings, seen);
        scanDexFiles(context, findings, seen);
        scanUsbDebugging(context, findings, seen);
        scanVpn(context, findings, seen);
        scanMockLocation(context, findings, seen);
        scanRom(findings, seen);
        if (signatures.platformEnabled) {
            scanPlatformCandidates(context, findings, seen);
        }
        return findings;
    }

    static boolean matchSuPath(String path, YidunSignatures signatures) {
        return path != null && signatures.suPaths.contains(path);
    }

    static boolean matchMountLine(String line, YidunSignatures signatures) {
        return matchMountMarker(line, signatures) != null;
    }

    static String matchMountMarker(String line, YidunSignatures signatures) {
        if (line == null) {
            return null;
        }
        String lower = line.toLowerCase(Locale.US);
        for (String marker : signatures.mountMarkers) {
            if (lower.contains(marker.toLowerCase(Locale.US))) {
                return marker;
            }
        }
        return null;
    }

    static boolean matchEmulatorPath(String path, YidunSignatures signatures) {
        return path != null && signatures.emulatorPaths.contains(path);
    }

    static boolean matchEmulatorBuild(String value, YidunSignatures signatures) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(Locale.US);
        for (String marker : signatures.emulatorBuildMarkers) {
            if (lower.contains(marker.toLowerCase(Locale.US))) {
                return true;
            }
        }
        return false;
    }

    static boolean matchEmulatorProperty(String name, YidunSignatures signatures) {
        return name != null && signatures.emulatorProperties.contains(name);
    }

    static String classifyMapsLine(String line, YidunSignatures signatures) {
        if (line == null) {
            return null;
        }
        String lower = line.toLowerCase(Locale.US);
        if (lower.contains("libshield") || lower.contains("libshadowhook")
                || lower.contains("shadowhook") || lower.contains("libyara")
                || lower.contains("forgemirror")) {
            return null;
        }
        for (String marker : signatures.hookMapsMarkers) {
            if (lower.contains(marker.toLowerCase(Locale.US))) {
                return ruleForHookMarker(marker);
            }
        }
        return null;
    }

    static String classifyHookClass(String dottedName, YidunSignatures signatures) {
        if (dottedName == null) {
            return null;
        }
        for (String entry : signatures.hookClasses) {
            String candidate = entry.replace('/', '.');
            if (candidate.equals(dottedName)) {
                return candidate.toLowerCase(Locale.US).contains("sandhook")
                        ? RULE_HOOK : RULE_XPOSED;
            }
        }
        return null;
    }

    static boolean matchLdPreload(String value, YidunSignatures signatures) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (String token : value.split("\\s+")) {
            if (token.isEmpty()) {
                continue;
            }
            String lower = token.toLowerCase(Locale.US);
            for (String marker : signatures.ldPreloadMarkers) {
                if (lower.contains(marker.toLowerCase(Locale.US))) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean matchCloudPhonePackage(String name, YidunSignatures signatures) {
        if (name == null) {
            return false;
        }
        for (String prefix : signatures.cloudPhonePrefixes) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static boolean matchCloudService(String name, YidunSignatures signatures) {
        return name != null && signatures.cloudServices.contains(name);
    }

    static boolean isUsbDebugging(int adbEnabled) {
        return adbEnabled == 1;
    }

    static boolean isMockLocationSetting(String value) {
        return value != null && !value.isEmpty()
                && !"0".equals(value) && !"null".equalsIgnoreCase(value);
    }

    static boolean isKnownMockLocationPackage(String name) {
        if (name == null) {
            return false;
        }
        for (String candidate : MOCK_LOCATION_PACKAGES) {
            if (candidate.equals(name)) {
                return true;
            }
        }
        return false;
    }

    static String classifyRom(String fingerprint, String brand, String device,
                              String product, String manufacturer) {
        String fp = lower(fingerprint);
        String b = lower(brand);
        String d = lower(device);
        if (isUnknownBuildField(b) || isUnknownBuildField(d)
                || isUnknownBuildField(lower(product))
                || isUnknownBuildField(lower(manufacturer))) {
            return "Build.field_unknown=BRAND:" + brand + ",DEVICE:" + device
                    + ",PRODUCT:" + product + ",MANUFACTURER:" + manufacturer;
        }
        String[] parts = fp.split("/");
        if (parts.length < 3) {
            return "Build.FINGERPRINT=malformed";
        }
        int colon = parts[2].indexOf(':');
        String fpDevice = colon < 0 ? parts[2] : parts[2].substring(0, colon);
        if (!parts[0].isEmpty() && !parts[0].equals(b)) {
            return "Build.FINGERPRINT.brand=" + parts[0] + ",Build.BRAND=" + b;
        }
        if (!fpDevice.isEmpty() && !fpDevice.equals(d)) {
            return "Build.FINGERPRINT.device=" + fpDevice + ",Build.DEVICE=" + d;
        }
        return null;
    }

    private static boolean isUnknownBuildField(String value) {
        return value.isEmpty() || "unknown".equals(value);
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.US);
    }

    static boolean hasProxyConfig(String httpProxy, String httpsProxy,
                                  String globalProxy, String interfaceName) {
        return validProxy(httpProxy) || validProxy(httpsProxy)
                || validProxy(globalProxy)
                || (interfaceName != null && isTunOrPpp(interfaceName));
    }

    static boolean isTunOrPpp(String name) {
        return name != null && (name.startsWith("tun") || name.startsWith("ppp"));
    }

    private static boolean validProxy(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        return !trimmed.isEmpty()
                && !":0".equals(trimmed)
                && !"0".equals(trimmed)
                && !"null".equalsIgnoreCase(trimmed);
    }

    static boolean hasCaptureCaMarker(String value) {
        String lowerValue = lower(value);
        for (String marker : CAPTURE_CA_MARKERS) {
            if (lowerValue.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    static boolean isKnownClonePackage(String name) {
        return contains(CLONE_PACKAGES, name);
    }

    static boolean isKnownCapturePackage(String name) {
        return contains(CAPTURE_PACKAGES, name);
    }

    static boolean isKnownScreenPackage(String name) {
        return contains(SCREEN_SHARE_PACKAGES, name);
    }

    static boolean isKnownAutomationPackage(String name) {
        return contains(AUTOMATION_PACKAGES, name);
    }

    private static boolean contains(String[] values, String name) {
        if (name == null) {
            return false;
        }
        for (String value : values) {
            if (value.equals(name)) {
                return true;
            }
        }
        return false;
    }

    static List<String> accessibilityPackages(String value) {
        List<String> packages = new ArrayList<>();
        if (value == null || value.isEmpty()) {
            return packages;
        }
        for (String entry : value.split(":")) {
            int slash = entry.indexOf('/');
            String name = (slash < 0 ? entry : entry.substring(0, slash)).trim();
            if (!name.isEmpty() && !packages.contains(name)) {
                packages.add(name);
            }
        }
        return packages;
    }

    static String classifyClone(int myUid, int expectedUid, String myDataDir,
                                String expectedDataDir, boolean managedProfile,
                                boolean knownClonePackage, boolean pathMarker) {
        if (managedProfile) {
            return null;
        }
        if (myUid != expectedUid) {
            return "uid:mismatch my=" + myUid + ",expected=" + expectedUid;
        }
        if (myDataDir != null && expectedDataDir != null
                && !myDataDir.equals(expectedDataDir)) {
            return "dataDir:mismatch my=" + myDataDir + ",expected=" + expectedDataDir;
        }
        if (knownClonePackage && pathMarker) {
            return "package+path";
        }
        return null;
    }

    static boolean isReadableMapLine(String line) {
        String[] fields = mapFields(line);
        if (fields == null || fields.length < 6
                || fields[1].length() < 4 || fields[1].charAt(0) != 'r') {
            return false;
        }
        String path = mapsPath(fields[5]);
        return path != null && path.startsWith("/");
    }

    static String mapsPath(String path) {
        if (path == null) {
            return null;
        }
        String value = path.trim();
        int deleted = value.indexOf(" (deleted)");
        if (deleted >= 0) {
            value = value.substring(0, deleted);
        }
        if (value.indexOf('!') >= 0) {
            return null;
        }
        return value.isEmpty() ? null : value;
    }

    static int elfMachine(byte[] header) {
        if (header == null || header.length < 20
                || header[0] != 0x7f || header[1] != 'E'
                || header[2] != 'L' || header[3] != 'F') {
            return -1;
        }
        boolean bigEndian = (header[5] & 0xff) == 2;
        int low = header[18] & 0xff;
        int high = header[19] & 0xff;
        return bigEndian ? (low << 8) | high : low | (high << 8);
    }

    static int elfMachine(File file) {
        try (InputStream input = new FileInputStream(file)) {
            byte[] header = new byte[20];
            return readFully(input, header) == header.length
                    ? elfMachine(header) : -1;
        } catch (Throwable ignored) {
            return -1;
        }
    }

    static boolean isNativeElfMachine(int machine) {
        return machine == 183      // AArch64
                || machine == 40   // ARM
                || machine == 62   // x86_64
                || machine == 3;   // x86
    }

    static String dexMagic(File file) {
        try (InputStream input = new FileInputStream(file)) {
            byte[] header = new byte[8];
            return readFully(input, header) == header.length
                    ? new String(header, StandardCharsets.ISO_8859_1) : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static boolean isStandardDexMagic(String magic, YidunSignatures signatures) {
        return magic != null && signatures.dexStandardMagic.contains(magic);
    }

    static String printable(String value) {
        if (value == null) {
            return "unreadable";
        }
        StringBuilder builder = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '\n') {
                builder.append("\\n");
            } else if (character == 0) {
                builder.append("\\0");
            } else if (character < 0x20 || character > 0x7e) {
                builder.append(String.format(Locale.US, "\\x%02x", (int) character));
            } else {
                builder.append(character);
            }
        }
        return builder.toString();
    }

    private static String[] mapFields(String line) {
        return line == null ? null : line.trim().split("\\s+", 6);
    }

    private static String mapField(String line) {
        String[] fields = mapFields(line);
        return fields != null && fields.length >= 6 ? fields[5] : null;
    }

    private static int readFully(InputStream input, byte[] buffer) throws Exception {
        int read = 0;
        while (read < buffer.length) {
            int count = input.read(buffer, read, buffer.length - read);
            if (count < 0) {
                break;
            }
            read += count;
        }
        return read;
    }

    static int tracerPid(String line) {
        if (line == null || !line.startsWith("TracerPid:")) {
            return -1;
        }
        try {
            return Integer.parseInt(line.substring("TracerPid:".length()).trim());
        } catch (NumberFormatException error) {
            return -1;
        }
    }

    static boolean isZombie(String line, YidunSignatures signatures) {
        return line != null && line.startsWith("State:")
                && !signatures.zombieMarker.isEmpty()
                && line.contains(signatures.zombieMarker);
    }

    private static String ruleForHookMarker(String marker) {
        String lower = marker.toLowerCase(Locale.US);
        if (lower.contains("xposed")) {
            return RULE_XPOSED;
        }
        if (lower.contains("frida")) {
            return RULE_HOOK;
        }
        return RULE_INJECTION;
    }

    private static String kindForHookRule(String ruleId) {
        if (RULE_XPOSED.equals(ruleId)) {
            return "xposed";
        }
        if (RULE_HOOK.equals(ruleId)) {
            return "hook";
        }
        return "injection";
    }

    private void scanRoot(List<Finding> findings, Set<String> seen) {
        for (String path : signatures.suPaths) {
            if (new File(path).exists()) {
                add(findings, seen, RULE_ROOT, "root", path, 0.7);
            }
        }
    }

    private void scanMounts(List<Finding> findings, Set<String> seen) {
        String mounts = readText("/proc/self/mounts");
        if (mounts.isEmpty()) {
            return;
        }
        Set<String> reportedMarkers = new LinkedHashSet<>();
        for (String line : mounts.split("\n")) {
            String marker = matchMountMarker(line, signatures);
            if (marker != null && reportedMarkers.add(marker)) {
                add(findings, seen, RULE_MOUNT, "root",
                        "mount:" + marker + ":" + line.trim(), 0.6);
            }
        }
    }

    private void scanTaskStatus(List<Finding> findings, Set<String> seen) {
        File tasks = new File("/proc/self/task");
        String[] entries = tasks.list();
        if (entries == null) {
            return;
        }
        boolean tracerReported = false;
        boolean zombieReported = false;
        int visited = 0;
        int myPid = Process.myPid();
        for (String tid : entries) {
            if (visited++ > MAX_TASKS) {
                break;
            }
            String status = readText("/proc/self/task/" + tid + "/status");
            if (status.isEmpty()) {
                continue;
            }
            for (String line : status.split("\n")) {
                int tracer = tracerPid(line);
                if (!tracerReported && tracer > 0 && tracer != myPid) {
                    add(findings, seen, RULE_DEBUG, "debugger",
                            "task:" + tid + ":TracerPid=" + tracer, 0.9);
                    tracerReported = true;
                }
                if (!zombieReported && isZombie(line, signatures)) {
                    add(findings, seen, RULE_DEBUG, "debugger",
                            "task:" + tid + ":zombie", 0.5);
                    zombieReported = true;
                }
            }
        }
    }

    private void scanSelfStatus(List<Finding> findings, Set<String> seen) {
        String status = readText("/proc/self/status");
        if (status.isEmpty()) {
            return;
        }
        for (String line : status.split("\n")) {
            for (String marker : signatures.statusMarkers) {
                if (line.startsWith(marker)) {
                    add(findings, seen, RULE_DEBUG, "debugger",
                            "status:" + line.trim(), 0.4);
                }
            }
        }
    }

    private void scanEmulatorPaths(List<Finding> findings, Set<String> seen) {
        for (String path : signatures.emulatorPaths) {
            if (new File(path).exists()) {
                add(findings, seen, RULE_EMULATOR, "emulator", path, 0.6);
            }
        }
    }

    private void scanEmulatorBuild(List<Finding> findings, Set<String> seen) {
        String[] values = {
                Build.FINGERPRINT, Build.MODEL, Build.HARDWARE,
                Build.PRODUCT, Build.DEVICE, Build.BRAND,
        };
        for (String value : values) {
            if (matchEmulatorBuild(value, signatures)) {
                add(findings, seen, RULE_EMULATOR, "emulator",
                        "Build=" + value, 0.5);
                return;
            }
        }
    }

    private void scanEmulatorProperties(List<Finding> findings, Set<String> seen) {
        for (String name : signatures.emulatorProperties) {
            String value = property(name);
            if (value != null && !value.isEmpty()) {
                add(findings, seen, RULE_EMULATOR, "emulator",
                        "property:" + name + "=" + value, 0.5);
            }
        }
    }

    private void scanMaps(String[] lines, List<Finding> findings, Set<String> seen) {
        if (lines.length == 0) {
            return;
        }
        Map<String, Integer> machines = new HashMap<>();
        for (String line : lines) {
            String ruleId = classifyMapsLine(line, signatures);
            if (ruleId == null || !isReadableMapLine(line)) {
                continue;
            }
            String path = mapsPath(mapField(line));
            if (path == null) {
                continue;
            }
            Integer machine = machines.get(path);
            if (machine == null) {
                if (machines.size() >= MAX_MAPS_FILES) {
                    continue;
                }
                machine = elfMachine(new File(path));
                machines.put(path, machine);
            }
            if (!isNativeElfMachine(machine)) {
                continue;
            }
            add(findings, seen, ruleId, kindForHookRule(ruleId), path, 0.8);
        }
    }

    private void scanHookClasses(List<Finding> findings, Set<String> seen) {
        for (String entry : signatures.hookClasses) {
            String dotted = entry.replace('/', '.');
            String ruleId = classifyHookClass(dotted, signatures);
            if (ruleId == null) {
                continue;
            }
            try {
                Class.forName(dotted, false, YidunProbe.class.getClassLoader());
                add(findings, seen, ruleId, kindForHookRule(ruleId),
                        "class:" + dotted, 0.8);
            } catch (Throwable ignored) {
                // Class not present.
            }
        }
    }

    private void scanHookServices(List<Finding> findings, Set<String> seen) {
        for (String name : signatures.hookServices) {
            if (serviceExists(name)) {
                add(findings, seen, RULE_XPOSED, "xposed",
                        "service:" + name, 0.8);
            }
        }
    }

    private void scanFileDescriptors(List<Finding> findings, Set<String> seen) {
        File dir = new File("/proc/self/fd");
        String[] entries = dir.list();
        if (entries == null) {
            return;
        }
        int visited = 0;
        for (String name : entries) {
            if (visited++ > MAX_FDS) {
                break;
            }
            try {
                String target = Os.readlink("/proc/self/fd/" + name);
                if (target == null) {
                    continue;
                }
                String lower = target.toLowerCase(Locale.US);
                for (String marker : signatures.fdMarkers) {
                    if (lower.contains(marker.toLowerCase(Locale.US))) {
                        add(findings, seen, RULE_INJECTION, "injection",
                                "fd:" + name + "->" + target, 0.7);
                        break;
                    }
                }
            } catch (Exception ignored) {
                // File descriptor closed while scanning.
            }
        }
    }

    private void scanLdPreload(List<Finding> findings, Set<String> seen) {
        String value = System.getenv("LD_PRELOAD");
        if (!matchLdPreload(value, signatures)) {
            return;
        }
        for (String token : value.split("\\s+")) {
            if (token.isEmpty()) {
                continue;
            }
            for (String marker : signatures.ldPreloadMarkers) {
                if (token.toLowerCase(Locale.US).contains(marker.toLowerCase(Locale.US))) {
                    add(findings, seen, RULE_LD_PRELOAD, "injection",
                            "LD_PRELOAD:" + token, 0.7);
                    break;
                }
            }
        }
    }

    private void scanCloudPhonePackages(Context context, List<Finding> findings,
                                        Set<String> seen) {
        if (context == null) {
            return;
        }
        try {
            PackageManager manager = context.getPackageManager();
            String[] packages = manager.getPackagesForUid(Process.myUid());
            if (packages == null) {
                return;
            }
            int visited = 0;
            for (String name : packages) {
                if (visited++ > MAX_PACKAGES) {
                    break;
                }
                if (matchCloudPhonePackage(name, signatures)) {
                    add(findings, seen, RULE_EMULATOR, "emulator",
                            "package:" + name, 0.5);
                }
            }
        } catch (Throwable error) {
            Log.w(TAG, "package probe unavailable: " + error);
        }
    }

    private void scanCloudServices(List<Finding> findings, Set<String> seen) {
        for (String name : signatures.cloudServices) {
            if (matchCloudService(name, signatures) && serviceExists(name)) {
                add(findings, seen, RULE_EMULATOR, "emulator",
                        "service:" + name, 0.7);
            }
        }
    }

    private void scanDex2oat(String[] lines, List<Finding> findings, Set<String> seen) {
        if (lines.length == 0 || signatures.dex2oatMarkers.isEmpty()) {
            return;
        }
        for (String line : lines) {
            String lower = line.toLowerCase(Locale.US);
            for (String marker : signatures.dex2oatMarkers) {
                if (lower.contains(marker.toLowerCase(Locale.US))) {
                    String path = mapsPath(mapField(line));
                    add(findings, seen, RULE_DEX, "dex",
                            "maps:" + marker + ":"
                                    + (path != null ? path : line.trim()), 0.4);
                    return;
                }
            }
        }
    }

    private void scanDexFiles(Context context, List<Finding> findings, Set<String> seen) {
        if (context == null) {
            return;
        }
        File[] entries;
        try {
            entries = context.getCodeCacheDir().listFiles();
        } catch (Throwable error) {
            Log.w(TAG, "dex cache probe unavailable: " + error);
            return;
        }
        if (entries == null) {
            return;
        }
        int visited = 0;
        for (File file : entries) {
            if (visited++ > MAX_DEX_FILES) {
                break;
            }
            if (!file.isFile() || !file.getName().endsWith(".dex")) {
                continue;
            }
            String magic = dexMagic(file);
            boolean standard = isStandardDexMagic(magic, signatures);
            add(findings, seen, RULE_DEX, "dex",
                    "dex:" + file.getAbsolutePath() + " magic=" + printable(magic),
                    standard ? 0.5 : 0.7);
        }
    }

    private void scanUsbDebugging(Context context, List<Finding> findings,
                                  Set<String> seen) {
        int enabled = 0;
        try {
            enabled = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0);
        } catch (Throwable error) {
            Log.w(TAG, "usb debug setting unavailable: " + error);
        }
        boolean debuggable = "1".equals(property("ro.debuggable"));
        if (isUsbDebugging(enabled)) {
            add(findings, seen, RULE_USB_DEBUG, "usb",
                    debuggable
                            ? "Settings.Global.ADB_ENABLED=1,ro.debuggable=1"
                            : "Settings.Global.ADB_ENABLED=1",
                    debuggable ? 0.7 : 0.5);
        } else if (debuggable) {
            add(findings, seen, RULE_USB_DEBUG, "usb", "ro.debuggable=1", 0.4);
        }
    }

    private void scanVpn(Context context, List<Finding> findings, Set<String> seen) {
        try {
            ConnectivityManager manager = (ConnectivityManager) context
                    .getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager == null) {
                return;
            }
            Network active = manager.getActiveNetwork();
            NetworkCapabilities activeCaps = active == null
                    ? null : manager.getNetworkCapabilities(active);
            if (activeCaps != null
                    && activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                add(findings, seen, RULE_VPN, "vpn",
                        "active-network:TRANSPORT_VPN", 0.7);
                return;
            }
            for (Network network : manager.getAllNetworks()) {
                NetworkCapabilities caps = manager.getNetworkCapabilities(network);
                if (caps != null
                        && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    add(findings, seen, RULE_VPN, "vpn",
                            "network:TRANSPORT_VPN", 0.7);
                    return;
                }
            }
        } catch (Throwable error) {
            Log.w(TAG, "vpn probe unavailable: " + error);
        }
    }

    private void scanMockLocation(Context context, List<Finding> findings,
                                  Set<String> seen) {
        ContentResolver resolver = context.getContentResolver();
        try {
            String mock = Settings.Secure.getString(resolver, "mock_location");
            if (isMockLocationSetting(mock)) {
                add(findings, seen, RULE_MOCK_LOCATION, "location",
                        "secure:mock_location=" + mock, 0.5);
            }
        } catch (Throwable error) {
            Log.w(TAG, "mock location setting unavailable: " + error);
        }
        PackageManager manager = context.getPackageManager();
        for (String name : MOCK_LOCATION_PACKAGES) {
            try {
                manager.getPackageInfo(name, 0);
                add(findings, seen, RULE_MOCK_LOCATION, "location",
                        "package:" + name, 0.4);
            } catch (PackageManager.NameNotFoundException ignored) {
                // Not installed.
            } catch (Throwable error) {
                Log.w(TAG, "mock package probe unavailable: " + error);
                break;
            }
        }
    }

    private void scanRom(List<Finding> findings, Set<String> seen) {
        String evidence = classifyRom(Build.FINGERPRINT, Build.BRAND, Build.DEVICE,
                Build.PRODUCT, Build.MANUFACTURER);
        if (evidence != null) {
            add(findings, seen, RULE_ROM, "rom", evidence, 0.4);
        }
    }

    private void scanPlatformCandidates(Context context, List<Finding> findings,
                                        Set<String> seen) {
        scanProxyAndCapture(context, findings, seen);
        scanClone(context, findings, seen);
        scanAutoTap(context, findings, seen);
        scanScreenShare(context, findings, seen);
    }

    private void scanProxyAndCapture(Context context, List<Finding> findings,
                                     Set<String> seen) {
        String globalProxy = null;
        try {
            globalProxy = Settings.Global.getString(context.getContentResolver(),
                    "http_proxy");
        } catch (Throwable ignored) {
            // Setting unavailable.
        }
        String interfaceName = findTunOrPppInterface();
        String httpProxy = System.getProperty("http.proxyHost");
        String httpsProxy = System.getProperty("https.proxyHost");
        boolean proxyConfigured = hasProxyConfig(httpProxy, httpsProxy,
                globalProxy, interfaceName);
        String captureCa = findCaptureCa();
        String capturePackage = firstKnownPackage(context, CAPTURE_PACKAGES);
        String proxyDetail = proxyEvidence(httpProxy, httpsProxy, globalProxy,
                interfaceName);
        if (proxyConfigured && captureCa != null) {
            add(findings, seen, RULE_PROXY, "proxy",
                    "proxy:" + proxyDetail + ",ca:" + captureCa, 0.7);
        } else if (proxyConfigured) {
            add(findings, seen, RULE_PROXY, "context",
                    "proxy:" + proxyDetail, 0.3);
        }
        if (capturePackage != null && captureCa != null) {
            add(findings, seen, RULE_PACKET_CAPTURE, "capture",
                    "package:" + capturePackage + ",ca:" + captureCa, 0.6);
        } else if (captureCa != null) {
            add(findings, seen, RULE_PACKET_CAPTURE, "context",
                    "ca:" + captureCa, 0.5);
        } else if (capturePackage != null) {
            add(findings, seen, RULE_PACKET_CAPTURE, "context",
                    "package:" + capturePackage, 0.3);
        }
    }

    private static String proxyEvidence(String httpProxy, String httpsProxy,
                                        String globalProxy, String interfaceName) {
        StringBuilder builder = new StringBuilder();
        if (validProxy(httpProxy)) {
            builder.append("http=").append(httpProxy).append(' ');
        }
        if (validProxy(httpsProxy)) {
            builder.append("https=").append(httpsProxy).append(' ');
        }
        if (validProxy(globalProxy)) {
            builder.append("global=").append(globalProxy).append(' ');
        }
        if (interfaceName != null) {
            builder.append("iface=").append(interfaceName);
        }
        return builder.toString().trim();
    }

    private void scanClone(Context context, List<Finding> findings, Set<String> seen) {
        try {
            PackageManager manager = context.getPackageManager();
            ApplicationInfo info = manager.getApplicationInfo(
                    context.getPackageName(), 0);
            boolean managed = false;
            if (Build.VERSION.SDK_INT >= 24) {
                UserManager users = (UserManager) context.getSystemService(
                        Context.USER_SERVICE);
                managed = users != null && users.isManagedProfile();
            }
            String myDataDir = context.getDataDir() == null
                    ? null : context.getDataDir().getAbsolutePath();
            String expectedDataDir = info.dataDir;
            boolean knownPackage = firstKnownPackage(context, CLONE_PACKAGES) != null;
            String path = lower(myDataDir) + "|" + lower(context.getPackageCodePath());
            boolean pathMarker = path.contains("clone")
                    || path.contains("parallel") || path.contains("virtual");
            String evidence = classifyClone(Process.myUid(), info.uid, myDataDir,
                    expectedDataDir, managed, knownPackage, pathMarker);
            if (evidence != null) {
                double confidence = evidence.startsWith("uid:") ? 0.7 : 0.5;
                add(findings, seen, RULE_CLONE, "clone", evidence, confidence);
            }
        } catch (Throwable error) {
            Log.w(TAG, "clone probe unavailable: " + error);
        }
    }

    private void scanAutoTap(Context context, List<Finding> findings,
                             Set<String> seen) {
        try {
            int enabled = Settings.Secure.getInt(context.getContentResolver(),
                    Settings.Secure.ACCESSIBILITY_ENABLED, 0);
            if (enabled != 1) {
                return;
            }
            String value = Settings.Secure.getString(context.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            List<String> packages = accessibilityPackages(value);
            if (!packages.isEmpty()) {
                Log.i(TAG, "accessibility services enabled count=" + packages.size());
            }
            for (String packageName : packages) {
                if (isKnownAutomationPackage(packageName)) {
                    add(findings, seen, RULE_AUTOTAP, "autotap",
                            "accessibility:" + packageName, 0.5);
                }
            }
        } catch (Throwable error) {
            Log.w(TAG, "accessibility probe unavailable: " + error);
        }
    }

    private void scanScreenShare(Context context, List<Finding> findings,
                                 Set<String> seen) {
        String packageName = firstKnownPackage(context, SCREEN_SHARE_PACKAGES);
        if (packageName != null) {
            add(findings, seen, RULE_SCREEN_SHARE, "screen",
                    "package:" + packageName, 0.3);
        }
    }

    private static String findTunOrPppInterface() {
        try {
            Enumeration<NetworkInterface> interfaces =
                    NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                return null;
            }
            while (interfaces.hasMoreElements()) {
                String name = interfaces.nextElement().getName();
                if (isTunOrPpp(name)) {
                    return name;
                }
            }
        } catch (Throwable ignored) {
            // Interface list unavailable.
        }
        return null;
    }

    private static String findCaptureCa() {
        try {
            KeyStore store = KeyStore.getInstance("AndroidCAStore");
            store.load(null, null);
            Enumeration<String> aliases = store.aliases();
            int visited = 0;
            while (aliases.hasMoreElements() && visited++ < 128) {
                String alias = aliases.nextElement();
                if (!alias.startsWith("user:")) {
                    continue;
                }
                KeyStore.Entry entry = store.getEntry(alias, null);
                if (!(entry instanceof KeyStore.TrustedCertificateEntry)) {
                    continue;
                }
                Certificate certificate = ((KeyStore.TrustedCertificateEntry) entry)
                        .getTrustedCertificate();
                if (!(certificate instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509 = (X509Certificate) certificate;
                String name = x509.getSubjectX500Principal().getName() + "|"
                        + x509.getIssuerX500Principal().getName();
                if (hasCaptureCaMarker(name)) {
                    return name;
                }
            }
        } catch (Throwable ignored) {
            // AndroidCAStore unavailable.
        }
        return null;
    }

    private static String firstKnownPackage(Context context, String[] names) {
        PackageManager manager = context.getPackageManager();
        for (String name : names) {
            try {
                manager.getPackageInfo(name, 0);
                return name;
            } catch (PackageManager.NameNotFoundException ignored) {
                // Not installed.
            } catch (Throwable error) {
                Log.w(TAG, "package probe unavailable: " + error);
                return null;
            }
        }
        return null;
    }

    private static void add(List<Finding> findings, Set<String> seen,
                            String ruleId, String kind, String evidence,
                            double confidence) {
        String key = ruleId + "|" + evidence;
        if (seen.add(key)) {
            findings.add(new Finding(ruleId, kind, evidence, confidence));
        }
    }

    private static volatile Method systemPropertyGet;
    private static volatile boolean systemPropertyResolved;
    private static volatile Method serviceManagerGet;
    private static volatile boolean serviceManagerResolved;

    private static String property(String name) {
        Method get = systemPropertyGet;
        if (!systemPropertyResolved) {
            synchronized (YidunProbe.class) {
                if (!systemPropertyResolved) {
                    try {
                        Class<?> properties = Class.forName("android.os.SystemProperties");
                        systemPropertyGet = properties.getMethod("get", String.class);
                    } catch (Throwable ignored) {
                        systemPropertyGet = null;
                    }
                    systemPropertyResolved = true;
                }
                get = systemPropertyGet;
            }
        }
        if (get == null) {
            return null;
        }
        try {
            Object value = get.invoke(null, name);
            return value instanceof String ? (String) value : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean serviceExists(String name) {
        Method getService = serviceManagerGet;
        if (!serviceManagerResolved) {
            synchronized (YidunProbe.class) {
                if (!serviceManagerResolved) {
                    try {
                        Class<?> manager = Class.forName("android.os.ServiceManager");
                        serviceManagerGet = manager.getMethod("getService", String.class);
                    } catch (Throwable ignored) {
                        serviceManagerGet = null;
                    }
                    serviceManagerResolved = true;
                }
                getService = serviceManagerGet;
            }
        }
        if (getService == null) {
            return false;
        }
        try {
            return getService.invoke(null, name) != null;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String readText(String path) {
        try (InputStream input = new FileInputStream(path)) {
            return new String(read(input, MAX_PROC_BYTES), StandardCharsets.UTF_8);
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static byte[] read(InputStream input, long limit) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long remaining = limit;
        int read;
        while (remaining > 0 && (read = input.read(chunk, 0,
                (int) Math.min(chunk.length, remaining))) != -1) {
            output.write(chunk, 0, read);
            remaining -= read;
        }
        return output.toByteArray();
    }

    private static String pathOf(String line) {
        int slash = line.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String path = line.substring(slash).trim();
        return path.isEmpty() ? null : path;
    }
}
