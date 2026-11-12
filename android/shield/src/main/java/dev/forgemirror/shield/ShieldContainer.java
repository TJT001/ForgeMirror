package dev.forgemirror.shield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Java FDX2 reader used by the P1-C prototype; native crypto moves to P2. */
final class ShieldContainer {
    private static final byte[] MAGIC = {'F', 'D', 'X', '2'};
    private static final int VERSION = 2;
    private static final int HEADER_SIZE = 128;
    private static final int ENTRY_SIZE = 72;
    private static final int CHUNK_SIZE = 65536;
    private static final int TAG_SIZE = 16;
    private static final int ALG_AES_256_GCM = 1;
    private static final int KDF_HKDF_SHA256 = 1;
    private static final int MAX_FILES = 64;
    private static final int MAX_CHUNKS = 32768;
    private static final long MAX_FILE = 1L << 30;
    private static final long MAX_TOTAL = 2L << 30;
    private static final byte[] TOC_LABEL = "FM/fdx2/toc/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] CHUNK_LABEL = "FM/fdx2/chunk/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private ShieldContainer() {
    }

    static byte[][] open(byte[] data, byte[] key) throws Exception {
        if (data.length < HEADER_SIZE) {
            throw new IllegalArgumentException("container too short");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[i] != MAGIC[i]) {
                throw new IllegalArgumentException("bad container magic");
            }
        }
        int version = Short.toUnsignedInt(buffer.getShort(4));
        int headerSize = Short.toUnsignedInt(buffer.getShort(6));
        int flags = buffer.getInt(8);
        int alg = data[12] & 0xff;
        int kdf = data[13] & 0xff;
        int reserved = Short.toUnsignedInt(buffer.getShort(14));
        int fileCount = buffer.getInt(32);
        int chunkSize = buffer.getInt(36);
        int totalChunks = buffer.getInt(72);
        long totalPlain = buffer.getLong(64);
        long tocOffset = buffer.getLong(80);
        long tocSize = buffer.getLong(88);

        if (version != VERSION || headerSize != HEADER_SIZE || flags != 0
                || alg != ALG_AES_256_GCM || kdf != KDF_HKDF_SHA256 || reserved != 0
                || buffer.getInt(60) != 0 || buffer.getInt(76) != 0) {
            throw new IllegalArgumentException("bad container header");
        }
        if (fileCount < 1 || fileCount > MAX_FILES || chunkSize != CHUNK_SIZE
                || totalChunks > MAX_CHUNKS || totalPlain > MAX_TOTAL) {
            throw new IllegalArgumentException("container limit exceeded");
        }
        if (tocOffset < HEADER_SIZE || tocOffset > data.length
                || tocSize != TAG_SIZE + (long) ENTRY_SIZE * fileCount
                || tocOffset + tocSize != data.length) {
            throw new IllegalArgumentException("bad TOC bounds");
        }

        byte[] buildId = new byte[16];
        System.arraycopy(data, 16, buildId, 0, 16);
        byte[] noncePrefix = new byte[8];
        System.arraycopy(data, 40, noncePrefix, 0, 8);
        byte[] tocNonce = new byte[12];
        System.arraycopy(data, 48, tocNonce, 0, 12);

        byte[] tocKey = hkdf(key, buildId, TOC_LABEL);
        byte[] chunkKey = hkdf(key, buildId, CHUNK_LABEL);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tocKey, "AES"),
                new GCMParameterSpec(128, tocNonce));
        cipher.updateAAD(data, 0, HEADER_SIZE);
        byte[] toc = cipher.doFinal(data, (int) tocOffset, (int) tocSize);
        if (toc.length != ENTRY_SIZE * fileCount) {
            throw new IllegalArgumentException("bad TOC length");
        }

        List<Entry> entries = new ArrayList<>(fileCount);
        long expectedOffset = HEADER_SIZE;
        int expectedChunks = 0;
        long expectedPlain = 0;
        ByteBuffer tocBuffer = ByteBuffer.wrap(toc).order(ByteOrder.LITTLE_ENDIAN);
        for (int index = 0; index < fileCount; index++) {
            int base = index * ENTRY_SIZE;
            int fileIndex = tocBuffer.getInt(base);
            int fileFlags = tocBuffer.getInt(base + 4);
            long size = tocBuffer.getLong(base + 16);
            int entryChunkSize = tocBuffer.getInt(base + 24);
            int chunkCount = tocBuffer.getInt(base + 28);
            long dataOffset = tocBuffer.getLong(base + 32);
            byte[] digest = new byte[32];
            System.arraycopy(toc, base + 40, digest, 0, 32);

            if (fileIndex != index || fileFlags != 0 || entryChunkSize != CHUNK_SIZE
                    || size < 0 || size > MAX_FILE
                    || chunkCount != (int) ((size + CHUNK_SIZE - 1) / CHUNK_SIZE)
                    || dataOffset != expectedOffset || dataOffset > tocOffset) {
                throw new IllegalArgumentException("bad TOC entry " + index);
            }
            long remaining = size;
            for (int i = 0; i < chunkCount; i++) {
                long span = Math.min(CHUNK_SIZE, remaining);
                expectedOffset += span + TAG_SIZE;
                remaining -= span;
            }
            if (expectedOffset > tocOffset) {
                throw new IllegalArgumentException("data region exceeds TOC");
            }
            expectedChunks += chunkCount;
            expectedPlain += size;
            entries.add(new Entry(size, digest));
        }
        if (expectedOffset != tocOffset || expectedChunks != totalChunks
                || expectedPlain != totalPlain) {
            throw new IllegalArgumentException("header totals mismatch");
        }

        byte[][] files = new byte[fileCount][];
        int cursor = HEADER_SIZE;
        int globalChunk = 0;
        for (int fileIndex = 0; fileIndex < fileCount; fileIndex++) {
            Entry entry = entries.get(fileIndex);
            byte[] plaintext = new byte[(int) entry.size];
            int written = 0;
            long remaining = entry.size;
            while (remaining > 0) {
                int length = (int) Math.min(CHUNK_SIZE, remaining);
                int ciphertextLength = length + TAG_SIZE;
                if (cursor + ciphertextLength > data.length) {
                    throw new IllegalArgumentException("truncated chunk");
                }
                byte[] nonce = new byte[12];
                System.arraycopy(noncePrefix, 0, nonce, 0, 8);
                nonce[8] = (byte) (globalChunk >>> 24);
                nonce[9] = (byte) (globalChunk >>> 16);
                nonce[10] = (byte) (globalChunk >>> 8);
                nonce[11] = (byte) globalChunk;
                byte[] aad = chunkAad(buildId, fileIndex, globalChunk, length);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chunkKey, "AES"),
                        new GCMParameterSpec(128, nonce));
                cipher.updateAAD(aad);
                byte[] chunk = cipher.doFinal(data, cursor, ciphertextLength);
                System.arraycopy(chunk, 0, plaintext, written, length);
                written += length;
                remaining -= length;
                cursor += ciphertextLength;
                globalChunk++;
            }
            if (!MessageDigest.isEqual(sha256(plaintext), entry.digest)) {
                throw new SecurityException("plaintext hash mismatch at index " + fileIndex);
            }
            files[fileIndex] = plaintext;
        }
        if (cursor != tocOffset) {
            throw new IllegalArgumentException("chunk region length mismatch");
        }
        return files;
    }

    private static byte[] chunkAad(byte[] buildId, int fileIndex, int chunkIndex, int plaintextLen) {
        ByteBuffer aad = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN);
        aad.put(MAGIC);
        aad.putShort((short) VERSION);
        aad.put((byte) ALG_AES_256_GCM);
        aad.put((byte) KDF_HKDF_SHA256);
        aad.put(buildId);
        aad.putInt(fileIndex);
        aad.putInt(chunkIndex);
        aad.putInt(plaintextLen);
        aad.putInt(0);
        return aad.array();
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 0x01);
        return mac.doFinal();
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static final class Entry {
        final long size;
        final byte[] digest;

        Entry(long size, byte[] digest) {
            this.size = size;
            this.digest = digest;
        }
    }
}
