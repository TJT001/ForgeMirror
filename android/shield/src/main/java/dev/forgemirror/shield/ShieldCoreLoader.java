package dev.forgemirror.shield;

import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;

import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.util.LinkedHashSet;
import java.util.Set;

/** Decrypts the per-ABI encrypted shield core and exposes it as a memfd. */
final class ShieldCoreLoader {
    static final byte[] MAGIC = {'F', 'M', 'C', '1'};

    private ShieldCoreLoader() {
    }

    static ParcelFileDescriptor open(Context context, ShieldConfig config, byte[] coreKey)
            throws Exception {
        if (config.core == null || config.core.isEmpty() || coreKey == null) {
            return null;
        }
        for (String abi : abis(context)) {
            byte[] blob;
            try {
                blob = ShieldAssets.read(context, config.core + "/" + abi + ".enc");
            } catch (Exception missing) {
                continue;
            }
            if (blob.length < MAGIC.length + 12 + 16) {
                continue;
            }
            for (int index = 0; index < MAGIC.length; index++) {
                if (blob[index] != MAGIC[index]) {
                    throw new SecurityException("bad core envelope");
                }
            }
            byte[] nonce = java.util.Arrays.copyOfRange(blob, 4, 16);
            byte[] ciphertext = java.util.Arrays.copyOfRange(blob, 16, blob.length);
            byte[] aad = java.util.Arrays.copyOfRange(blob, 0, 16);
            byte[] plaintext = ShieldCrypto.gcmDecrypt(coreKey, nonce, ciphertext, aad);
            FileDescriptor fd = Os.memfd_create("fm-core", 0);
            int offset = 0;
            while (offset < plaintext.length) {
                int written = Os.write(fd, plaintext, offset, plaintext.length - offset);
                if (written <= 0) {
                    throw new IllegalStateException("core memfd write stalled");
                }
                offset += written;
            }
            Os.lseek(fd, 0, OsConstants.SEEK_SET);
            ParcelFileDescriptor descriptor = ParcelFileDescriptor.dup(fd);
            Os.close(fd);
            return descriptor;
        }
        throw new FileNotFoundException("encrypted core asset not found");
    }

    private static String[] abis(Context context) {
        Set<String> values = new LinkedHashSet<>();
        boolean is64 = android.os.Process.is64Bit();
        if (is64) {
            values.add("arm64-v8a");
            values.add("x86_64");
        } else {
            values.add("armeabi-v7a");
            values.add("x86");
        }
        if (Build.SUPPORTED_ABIS != null) {
            java.util.Collections.addAll(values, Build.SUPPORTED_ABIS);
        }
        return values.toArray(new String[0]);
    }
}
