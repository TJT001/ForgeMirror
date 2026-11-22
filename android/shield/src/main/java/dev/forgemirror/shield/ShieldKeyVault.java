package dev.forgemirror.shield;

import java.util.Arrays;

/** Native key vault: white-box unwrap, HKDF and FDX2 decryption live in libshield_boot. */
final class ShieldKeyVault {
    static final String TABLE_ASSET = "shield/wbaes.table";
    static final int DERIVE_POLICY = 1;
    static final int DERIVE_FILE = 2;
    static final int DERIVE_NATIVE = 3;
    static final int DERIVE_RULES = 4;
    static final int DERIVE_CORE = 5;
    private static final byte[] MAGIC = {'W', 'B', 'K', '1'};
    private static final int BLOB_SIZE = 4 + 12 + 32;

    private ShieldKeyVault() {
    }

    static boolean isWrapped(byte[] blob) {
        return blob != null && blob.length == BLOB_SIZE
                && Arrays.equals(Arrays.copyOf(blob, MAGIC.length), MAGIC);
    }

    static void installWrapped(byte[] blob, byte[] table) {
        if (!nativeInstall(blob, table)) {
            throw new SecurityException("white-box key unwrap failed");
        }
    }

    static void installRaw(byte[] key) {
        if (!nativeInstallRaw(key)) {
            throw new SecurityException("content key install failed");
        }
    }

    static byte[] derive(int id, byte[] buildId) {
        byte[] key = nativeDerive(id, buildId);
        if (key == null || key.length != 32) {
            throw new SecurityException("key derivation failed");
        }
        return key;
    }

    static byte[][] openContainer(byte[] container) {
        byte[][] files = nativeOpenContainer(container);
        if (files == null) {
            throw new SecurityException("container decryption failed");
        }
        return files;
    }

    /**
     * Decrypts a signed package envelope in the native vault. Layout:
     * header(headerSize, also the AAD) with a 12-byte nonce at nonceOffset,
     * ciphertext, then sigSize bytes of trailing signature. The tag is the
     * last 16 bytes of the ciphertext region.
     */
    static byte[] decryptPackage(int id, byte[] buildId, byte[] pkg,
                                 int headerSize, int nonceOffset, int sigSize) {
        byte[] plain = nativeDecryptPackage(id, buildId, pkg, headerSize,
                nonceOffset, sigSize);
        if (plain == null) {
            throw new SecurityException("package decryption failed");
        }
        return plain;
    }

    static void clear() {
        nativeClear();
    }

    private static native boolean nativeInstall(byte[] blob, byte[] table);
    private static native boolean nativeInstallRaw(byte[] key);
    private static native byte[] nativeDerive(int id, byte[] buildId);
    private static native byte[][] nativeOpenContainer(byte[] container);
    private static native byte[] nativeDecryptPackage(int id, byte[] buildId,
                                                       byte[] pkg, int headerSize,
                                                       int nonceOffset, int sigSize);
    private static native void nativeClear();
}
