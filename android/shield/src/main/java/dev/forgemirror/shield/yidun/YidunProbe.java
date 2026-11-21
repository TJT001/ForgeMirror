package dev.forgemirror.shield.yidun;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import android.system.Os;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

    private static final String TAG = "YidunProbe";
    private static final long MAX_PROC_BYTES = 8L << 20;
    private static final int MAX_FDS = 256;
    private static final int MAX_TASKS = 512;
    private static final int MAX_PACKAGES = 128;
    private static final int MAX_MAPS_FILES = 64;
    private static final int MAX_DEX_FILES = 64;

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
