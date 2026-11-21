package dev.forgemirror.shield;

import android.content.Context;

import com.risid.wbaes.AES;
import com.risid.wbaes.State;

import java.io.ByteArrayInputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;

/** White-box wrapped content-key vault. */
final class ShieldWhitebox {
    static final byte[] MAGIC = {'W', 'B', 'K', '1'};
    static final int NONCE_SIZE = 12;
    static final int KEY_SIZE = 32;
    static final String TABLE_ASSET = "shield/wbaes.table";

    private static volatile AES table;

    private ShieldWhitebox() {
    }

    static boolean isWrapped(byte[] blob) {
        return blob != null && blob.length == MAGIC.length + NONCE_SIZE + KEY_SIZE
                && Arrays.equals(Arrays.copyOf(blob, MAGIC.length), MAGIC);
    }

    static byte[] unwrap(Context context, byte[] blob) throws Exception {
        if (!isWrapped(blob)) {
            throw new IllegalArgumentException("not a white-box key blob");
        }
        byte[] nonce = Arrays.copyOfRange(blob, MAGIC.length,
                MAGIC.length + NONCE_SIZE);
        byte[] wrapped = Arrays.copyOfRange(blob, MAGIC.length + NONCE_SIZE,
                blob.length);
        byte[] stream = keystream(context, nonce, wrapped.length);
        byte[] key = new byte[wrapped.length];
        for (int index = 0; index < key.length; index++) {
            key[index] = (byte) (wrapped[index] ^ stream[index]);
        }
        Arrays.fill(stream, (byte) 0);
        return key;
    }

    private static byte[] keystream(Context context, byte[] nonce, int length)
            throws Exception {
        AES aes = table(context);
        byte[] out = new byte[length];
        byte[] block = new byte[16];
        System.arraycopy(nonce, 0, block, 0, NONCE_SIZE);
        synchronized (aes) {
            for (int offset = 0, counter = 0; offset < length;
                 offset += 16, counter++) {
                block[12] = (byte) (counter >>> 24);
                block[13] = (byte) (counter >>> 16);
                block[14] = (byte) (counter >>> 8);
                block[15] = (byte) counter;
                State state = new State(block, true, false);
                state.transpose();
                aes.crypt(state);
                byte[] stream = state.getStateCopy();
                System.arraycopy(stream, 0, out, offset,
                        Math.min(16, length - offset));
            }
        }
        return out;
    }

    private static AES table(Context context) throws Exception {
        AES current = table;
        if (current != null) {
            return current;
        }
        synchronized (ShieldWhitebox.class) {
            current = table;
            if (current == null) {
                byte[] serialized = ShieldAssets.read(context, TABLE_ASSET);
                try (ObjectInputStream input = new ObjectInputStream(
                        new ByteArrayInputStream(serialized)) {
                    @Override
                    protected Class<?> resolveClass(ObjectStreamClass desc)
                            throws java.io.IOException, ClassNotFoundException {
                        if (!allowed(desc.getName())) {
                            throw new InvalidClassException(desc.getName(),
                                    "outside white-box table");
                        }
                        return super.resolveClass(desc);
                    }
                }) {
                    current = (AES) input.readObject();
                }
                table = current;
            }
            return current;
        }
    }

    private static boolean allowed(String descriptor) {
        String name = descriptor;
        while (name.startsWith("[")) {
            name = name.substring(1);
        }
        if (name.startsWith("L") && name.endsWith(";")) {
            name = name.substring(1, name.length() - 1);
        }
        if (name.length() == 1) {
            return "BIJSZCFD".contains(name);
        }
        return name.startsWith("com.risid.wbaes.");
    }
}
