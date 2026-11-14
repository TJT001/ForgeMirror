package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * In-memory ELF loading: encrypted native libraries are decrypted into an
 * anonymous memfd and handed to the platform linker through /proc/self/fd.
 */
final class ShieldNativeLoader {
    static final byte[] MAGIC = {'F', 'M', 'N', '1'};
    private static final byte[] LABEL =
            "FM/native/v1".getBytes(StandardCharsets.US_ASCII);
    private static final String TAG = "ShieldNativeLoader";
    private static final Map<String, String> LOADED = new HashMap<>();
    private static final Set<String> PRELOADED = new HashSet<>();


    private ShieldNativeLoader() {
    }

    static synchronized String findLibrary(Context context, String apkPath,
                                           String[] abis, String mapped,
                                           byte[] nativeKey, ClassLoader loader) {
        if (nativeKey == null || apkPath == null || mapped == null) {
            return null;
        }
        String cacheKey = apkPath + "!" + mapped;
        String cached = LOADED.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        try (ZipFile apk = new ZipFile(apkPath)) {
            for (String abi : abis) {
                String name = "assets/shield/native/" + abi + "/" + mapped + ".enc";
                ZipEntry entry = apk.getEntry(name);
                if (entry == null) {
                    continue;
                }
                byte[] blob = read(apk.getInputStream(entry));
                byte[] elf = decrypt(blob, nativeKey);
                preloadDependencies(apk, abis, elf, mapped, nativeKey,
                        new HashSet<>());
                String holder = "libshield_holder_" + hex(digest(mapped)) + ".so";
                if (hasJniOnLoad(elf)) {
                    String path = writeTemporary(context, holder, elf);
                    if (path != null) {
                        LOADED.put(cacheKey, path);
                        Log.i(TAG, "loaded from temporary file " + mapped);
                        return path;
                    }
                }
                long handle = ShieldRuntime.nativeLoadInMemory(elf, mapped, false);
                if (handle == 0) {
                    continue;
                }
                registerNatives(callerClass(loader), handle);
                String path = apkPath + "!/lib/" + abi + "/" + holder;
                if (apk.getEntry("lib/" + abi + "/" + holder) == null) {
                    path = apkPath + "!/lib/" + abi + "/libshield_dummy.so";
                }
                LOADED.put(cacheKey, path);
                Log.i(TAG, "loaded from memfd " + mapped);
                return path;
            }
        } catch (Exception error) {
            Log.w(TAG, "native asset load failed: " + error);
        }
        return null;
    }

    static synchronized String openNativePath(Context context, String mapped) {
        byte[] nativeKey = ShieldRuntime.nativeKey();
        if (context == null || mapped == null || nativeKey == null) {
            return null;
        }
        String apkPath = context.getApplicationInfo().sourceDir;
        String[] abis = android.os.Build.SUPPORTED_ABIS;
        try (ZipFile apk = new ZipFile(apkPath)) {
            String entry = findAsset(apk, abis, mapped);
            if (entry == null) {
                return null;
            }
            byte[] blob = read(apk.getInputStream(apk.getEntry(entry)));
            byte[] elf = decrypt(blob, nativeKey);
            preloadDependencies(apk, abis, elf, mapped, nativeKey,
                    new HashSet<>());
            String holder = "libshield_holder_" + hex(digest(mapped)) + ".so";
            return writeTemporary(context, holder, elf);
        } catch (Exception error) {
            Log.w(TAG, "openNativePath failed " + mapped + ": " + error);
            return null;
        }
    }

    private static void preloadDependencies(ZipFile apk, String[] abis,
                                            byte[] elf, String owner,
                                            byte[] nativeKey, Set<String> stack) {
        if (!stack.add(owner)) {
            return;
        }
        for (String dependency : needed(elf)) {
            if (dependency.equals(owner) || stack.contains(dependency)
                    || ShieldRuntime.nativeKey() == null) {
                continue;
            }
            String entry = findAsset(apk, abis, dependency);
            if (entry == null) {
                continue;
            }
            synchronized (PRELOADED) {
                if (PRELOADED.contains(dependency)) {
                    continue;
                }
                PRELOADED.add(dependency);
            }
            try {
                byte[] dependencyElf = decrypt(read(apk.getInputStream(
                        apk.getEntry(entry))), nativeKey);
                preloadDependencies(apk, abis, dependencyElf, dependency,
                        nativeKey, stack);
                if (ShieldRuntime.nativeLoadInMemory(dependencyElf, dependency,
                        true) == 0) {
                    PRELOADED.remove(dependency);
                }
            } catch (Exception error) {
                PRELOADED.remove(dependency);
                Log.w(TAG, "dependency preload failed " + dependency + ": " + error);
            }
        }
    }

    private static String findAsset(ZipFile apk, String[] abis, String mapped) {
        for (String abi : abis) {
            String name = "assets/shield/native/" + abi + "/" + mapped + ".enc";
            if (apk.getEntry(name) != null) {
                return name;
            }
        }
        return null;
    }

    private static List<String> needed(byte[] elf) {
        List<String> result = new ArrayList<>();
        if (elf == null || elf.length < 0x40 || elf[0] != 0x7f
                || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
            return result;
        }
        boolean is64 = elf[4] == 2;
        ByteBuffer buffer = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        long phoff = is64 ? buffer.getLong(0x20)
                : Integer.toUnsignedLong(buffer.getInt(0x1c));
        int phentsize = Short.toUnsignedInt(
                buffer.getShort(is64 ? 0x36 : 0x2a));
        int phnum = Short.toUnsignedInt(buffer.getShort(is64 ? 0x38 : 0x2c));
        List<long[]> loads = new ArrayList<>();
        long dynamicOffset = -1;
        long dynamicSize = 0;
        for (int index = 0; index < phnum; index++) {
            int position = (int) (phoff + (long) index * phentsize);
            if (position < 0 || position + phentsize > elf.length) {
                return result;
            }
            int type = buffer.getInt(position);
            long offset;
            long vaddr;
            long filesz;
            if (is64) {
                offset = buffer.getLong(position + 8);
                vaddr = buffer.getLong(position + 16);
                filesz = buffer.getLong(position + 32);
            } else {
                offset = Integer.toUnsignedLong(buffer.getInt(position + 4));
                vaddr = Integer.toUnsignedLong(buffer.getInt(position + 8));
                filesz = Integer.toUnsignedLong(buffer.getInt(position + 16));
            }
            if (type == 1) {
                loads.add(new long[]{offset, vaddr, filesz});
            } else if (type == 2) {
                dynamicOffset = offset;
                dynamicSize = filesz;
            }
        }
        if (dynamicOffset < 0 || dynamicSize <= 0) {
            return result;
        }
        int entrySize = is64 ? 16 : 8;
        long strtab = -1;
        List<Integer> offsets = new ArrayList<>();
        for (long position = dynamicOffset;
             position + entrySize <= dynamicOffset + dynamicSize;
             position += entrySize) {
            int tag = buffer.getInt((int) position);
            long value = is64 ? buffer.getLong((int) position + 8)
                    : Integer.toUnsignedLong(buffer.getInt((int) position + 4));
            if (tag == 0) {
                break;
            }
            if (tag == 1) {
                offsets.add((int) value);
            } else if (tag == 5) {
                strtab = value;
            }
        }
        if (strtab < 0) {
            return result;
        }
        long stringOffset = -1;
        for (long[] load : loads) {
            if (strtab >= load[1] && strtab < load[1] + load[2]) {
                stringOffset = load[0] + (strtab - load[1]);
                break;
            }
        }
        if (stringOffset < 0) {
            return result;
        }
        for (int relative : offsets) {
            int start = (int) (stringOffset + relative);
            if (start < 0 || start >= elf.length) {
                continue;
            }
            int end = start;
            while (end < elf.length && elf[end] != 0) {
                end++;
            }
            result.add(new String(elf, start, end - start, StandardCharsets.UTF_8));
        }
        return result;
    }

    static void cleanup(Context context) {
        File directory = new File(context.getCacheDir(), "shield-native");
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        }
    }

    private static boolean hasJniOnLoad(byte[] elf) {
        byte[] needle = {'J', 'N', 'I', '_', 'O', 'n', 'L', 'o', 'a', 'd'};
        outer:
        for (int index = 0; index <= elf.length - needle.length; index++) {
            for (int cursor = 0; cursor < needle.length; cursor++) {
                if (elf[index + cursor] != needle[cursor]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static String writeTemporary(Context context, String name, byte[] elf) {
        File directory = new File(context.getCacheDir(), "shield-native");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            return null;
        }
        File target = new File(directory, name);
        try (FileOutputStream output = new FileOutputStream(target)) {
            output.write(elf);
            output.getFD().sync();
        } catch (Exception error) {
            Log.w(TAG, "temporary native write failed: " + error);
            return null;
        }
        final File remove = target;
        new Thread(() -> {
            try {
                Thread.sleep(10000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
            //noinspection ResultOfMethodCallIgnored
            remove.delete();
        }, "shield-native-cleanup").start();
        return target.getAbsolutePath();
    }

    private static Class<?> callerClass(ClassLoader loader) {
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String name = frame.getClassName();
            if (name.startsWith("java.") || name.startsWith("dalvik.")
                    || name.startsWith("android.")
                    || name.startsWith("com.android.")
                    || name.startsWith("dev.forgemirror.shield.")) {
                continue;
            }
            try {
                return Class.forName(name, false, loader);
            } catch (Throwable ignored) {
                // Try the next frame.
            }
        }
        return null;
    }

    private static void registerNatives(Class<?> type, long handle) {
        if (type == null) {
            return;
        }
        List<String> names = new ArrayList<>();
        List<String> signatures = new ArrayList<>();
        List<String> symbols = new ArrayList<>();
        List<String> longSymbols = new ArrayList<>();
        for (Method method : type.getDeclaredMethods()) {
            if (!Modifier.isNative(method.getModifiers())) {
                continue;
            }
            String signature = signature(method);
            String base = "Java_" + mangle(type.getName().replace('.', '/'))
                    + "_" + mangle(method.getName());
            names.add(method.getName());
            signatures.add(signature);
            symbols.add(base);
            longSymbols.add(base + "__" + mangle(arguments(method)));
        }
        if (names.isEmpty()) {
            return;
        }
        nativeRegister(type, names.toArray(new String[0]),
                signatures.toArray(new String[0]),
                symbols.toArray(new String[0]), handle);
        nativeRegister(type, names.toArray(new String[0]),
                signatures.toArray(new String[0]),
                longSymbols.toArray(new String[0]), handle);
    }

    private static String arguments(Method method) {
        StringBuilder result = new StringBuilder();
        for (Class<?> parameter : method.getParameterTypes()) {
            result.append(descriptor(parameter));
        }
        return result.toString();
    }

    private static String signature(Method method) {
        StringBuilder result = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) {
            result.append(descriptor(parameter));
        }
        result.append(')').append(descriptor(method.getReturnType()));
        return result.toString();
    }

    private static String descriptor(Class<?> type) {
        if (type == void.class) return "V";
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == long.class) return "J";
        if (type == float.class) return "F";
        if (type == double.class) return "D";
        return "L" + type.getName().replace('.', '/') + ";";
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception error) {
            return new byte[0];
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < Math.min(value.length, 8); index++) {
            result.append(String.format(java.util.Locale.US, "%02x", value[index] & 0xff));
        }
        return result.toString();
    }

    private static String mangle(String value) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            switch (current) {
                case '/': result.append('_'); break;
                case '_': result.append("_1"); break;
                case ';': result.append("_2"); break;
                case '[': result.append("_3"); break;
                default: result.append(current);
            }
        }
        return result.toString();
    }

    private static byte[] decrypt(byte[] blob, byte[] key) throws Exception {
        if (blob == null || blob.length < MAGIC.length + 12 + 16) {
            throw new SecurityException("native envelope too short");
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (blob[index] != MAGIC[index]) {
                throw new SecurityException("bad native envelope");
            }
        }
        byte[] nonce = Arrays.copyOfRange(blob, 4, 16);
        byte[] ciphertext = Arrays.copyOfRange(blob, 16, blob.length);
        byte[] aad = Arrays.copyOfRange(blob, 0, 16);
        return ShieldCrypto.gcmDecrypt(key, nonce, ciphertext, aad);
    }

    private static byte[] read(InputStream input) throws Exception {
        try (InputStream stream = input;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = stream.read(buffer)) >= 0) {
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        }
    }

    private static native int nativeRegister(Class<?> type, String[] names,
                                             String[] signatures, String[] symbols,
                                             long handle);
}
