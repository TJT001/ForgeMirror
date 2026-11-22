package com.risid.wbaes;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
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

    private static void writeInt(DataOutputStream out, int value) throws Exception {
        out.write(value & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 24) & 0xFF);
    }

    private static void expect(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    /** Exports the Java object graph as the flat table the native vault reads. */
    private static void export(String tablePath, String outPath) throws Exception {
        AES aes = load(tablePath);
        T1Box[][] t1 = aes.getT1();
        T2Box[][] t2 = aes.getT2();
        T3Box[][] t3 = aes.getT3();
        XORCascade[][] xor = aes.getXor();
        XORCascadeState[] xorState = aes.getXorState();
        expect(t1.length == 2 && t2.length == 10 && t3.length == 10,
                "unexpected round count");
        for (int round = 0; round < t2.length; round++) {
            expect(t2[round].length == 16 && t3[round].length == 16,
                    "unexpected box count");
        }
        expect(xor.length == 10 && xorState.length == 2, "unexpected cascade count");

        try (DataOutputStream out = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(outPath)))) {
            out.write(new byte[]{'W', 'B', 'X', '1'});
            writeInt(out, 1);
            writeInt(out, 2 * 16 * 256 * 16);
            writeInt(out, 10 * 16 * 256 * 4);
            writeInt(out, 10 * 16 * 256 * 4);
            writeInt(out, 10 * 8 * 3 * 8 * 256);
            writeInt(out, 2 * 15 * 32 * 256);
            writeInt(out, 0);

            for (T1Box[] boxes : t1) {
                for (T1Box box : boxes) {
                    State[] rows = box.getTbl();
                    expect(rows.length == 256, "unexpected T1 rows");
                    for (State row : rows) {
                        out.write(row.getState(), 0, 16);
                    }
                }
            }
            for (T2Box[] boxes : t2) {
                for (T2Box box : boxes) {
                    long[] rows = box.getTbl();
                    expect(rows.length == 256, "unexpected T2 rows");
                    for (long row : rows) {
                        writeInt(out, (int) row);
                    }
                }
            }
            for (T3Box[] boxes : t3) {
                for (T3Box box : boxes) {
                    long[] rows = box.getTbl();
                    expect(rows.length == 256, "unexpected T3 rows");
                    for (long row : rows) {
                        writeInt(out, (int) row);
                    }
                }
            }
            for (XORCascade[] cascades : xor) {
                for (XORCascade cascade : cascades) {
                    XORBox[] boxes = cascade.getX();
                    expect(boxes.length == 3, "unexpected XOR boxes");
                    for (XORBox box : boxes) {
                        byte[][] rows = box.getTbl();
                        expect(rows.length == 8, "unexpected XOR rows");
                        for (byte[] row : rows) {
                            out.write(row, 0, 256);
                        }
                    }
                }
            }
            for (XORCascadeState cascade : xorState) {
                XORBoxState[] boxes = cascade.getX();
                expect(boxes.length == 15, "unexpected XOR state boxes");
                for (XORBoxState box : boxes) {
                    byte[][] rows = box.getTbl();
                    expect(rows.length == 32, "unexpected XOR state rows");
                    for (byte[] row : rows) {
                        out.write(row, 0, 256);
                    }
                }
            }
        }
    }

    private static void generate(byte[] key, String outPath) throws Exception {
        if (key.length != 16) {
            throw new IllegalArgumentException("table key must be 16 bytes");
        }
        com.risid.wbaes.generator.Generator generator =
                new com.risid.wbaes.generator.Generator();
        com.risid.wbaes.generator.ExternalBijections extc =
                new com.risid.wbaes.generator.ExternalBijections();
        generator.generateExtEncoding(extc,
                com.risid.wbaes.generator.Generator.WBAESGEN_EXTGEN_ID);
        generator.setUseIO04x04Identity(true);
        generator.setUseIO08x08Identity(true);
        generator.setUseMB08x08Identity(true);
        generator.setUseMB32x32Identity(true);
        generator.generate(true, key, 16, extc);
        AES table = generator.getAESi();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(
                buffer)) {
            out.writeObject(table);
        }
        byte[] serialized = buffer.toByteArray();
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(outPath)) {
            out.write(serialized);
        }
        java.util.Arrays.fill(serialized, (byte) 0);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && "generate".equals(args[0])) {
            generate(readKey(args[1]), args[2]);
            return;
        }
        if (args.length == 3 && "export".equals(args[0])) {
            export(args[1], args[2]);
            return;
        }
        if (args.length != 5) {
            System.err.println(
                    "usage: wrap|unwrap table keyHex|- nonceHex out\n"
                            + "       generate keyHex|- outTable\n"
                            + "       export table out");
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
