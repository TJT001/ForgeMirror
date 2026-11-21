package com.risid.wbaes;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Build-time CTR wrapper using the same white-box table as the runtime. */
public final class WhiteboxKeyTool {
    private static final byte[] MAGIC = {'W', 'B', 'K', '1'};

    private WhiteboxKeyTool() {
    }

    private static byte[] hex(String value) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException("hex length");
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
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

    private static AES load(String path) throws Exception {
        try (ObjectInputStream input = new ObjectInputStream(
                new FileInputStream(path)) {
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
            return (AES) input.readObject();
        }
    }

    private static byte[] readKey(String value) throws Exception {
        String hex = value;
        if ("-".equals(value)) {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
                hex = reader.readLine();
            }
        }
        if (hex == null) {
            throw new IllegalArgumentException("missing key");
        }
        return hex(hex.trim());
    }

    private static byte[] keystream(AES aes, byte[] nonce, int length) {
        byte[] out = new byte[length];
        byte[] block = new byte[16];
        System.arraycopy(nonce, 0, block, 0, 12);
        for (int offset = 0, counter = 0; offset < length; offset += 16, counter++) {
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
        return out;
    }

    private static byte[] crypt(AES aes, byte[] key, byte[] nonce) {
        byte[] stream = keystream(aes, nonce, key.length);
        byte[] out = new byte[key.length];
        for (int i = 0; i < key.length; i++) {
            out[i] = (byte) (key[i] ^ stream[i]);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.err.println(
                    "usage: wrap|unwrap table keyHex|- nonceHex out");
            System.exit(2);
        }
        boolean wrap = "wrap".equals(args[0]);
        AES aes = load(args[1]);
        byte[] key = readKey(args[2]);
        byte[] nonce = hex(args[3]);
        if (key.length != 32) {
            throw new IllegalArgumentException("content key must be 32 bytes");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("nonce must be 12 bytes");
        }
        byte[] output;
        if (wrap) {
            byte[] wrapped = crypt(aes, key, nonce);
            output = new byte[MAGIC.length + nonce.length + wrapped.length];
            System.arraycopy(MAGIC, 0, output, 0, MAGIC.length);
            System.arraycopy(nonce, 0, output, MAGIC.length, nonce.length);
            System.arraycopy(wrapped, 0, output, MAGIC.length + nonce.length,
                    wrapped.length);
        } else {
            output = null;
        }
        if (output != null) {
            try (FileOutputStream stream = new FileOutputStream(args[4])) {
                stream.write(output);
            }
        } else {
            byte[] body = Files.readAllBytes(Paths.get(args[4]));
            if (body.length != MAGIC.length + 12 + key.length) {
                throw new IllegalArgumentException("bad wrapped length");
            }
            byte[] wrapped = new byte[key.length];
            System.arraycopy(body, MAGIC.length + 12, wrapped, 0, wrapped.length);
            byte[] plain = crypt(aes, wrapped, nonce);
            try (FileOutputStream stream = new FileOutputStream(args[4] + ".out")) {
                stream.write(plain);
            }
        }
    }
}
