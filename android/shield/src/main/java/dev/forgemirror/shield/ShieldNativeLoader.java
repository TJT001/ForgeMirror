package dev.forgemirror.shield;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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


    private ShieldNativeLoader() {
    }

    static synchronized String findLibrary(String apkPath, String[] abis,
                                           String mapped, byte[] nativeKey,
                                           ClassLoader loader) {
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
                long handle = ShieldRuntime.nativeLoadInMemory(elf, mapped);
                if (handle == 0) {
                    continue;
                }
                registerNatives(callerClass(loader), handle);
                String holder = "libshield_holder_" + hex(digest(mapped)) + ".so";
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
        for (Method method : type.getDeclaredMethods()) {
            if (!Modifier.isNative(method.getModifiers())) {
                continue;
            }
            String signature = signature(method);
            names.add(method.getName());
            signatures.add(signature);
            symbols.add("Java_" + mangle(type.getName().replace('.', '/'))
                    + "_" + mangle(method.getName()));
        }
        if (names.isEmpty()) {
            return;
        }
        nativeRegister(type, names.toArray(new String[0]),
                signatures.toArray(new String[0]),
                symbols.toArray(new String[0]), handle);
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
