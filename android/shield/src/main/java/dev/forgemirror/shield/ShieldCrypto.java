package dev.forgemirror.shield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** HKDF, AES-GCM, and the FMF1 encrypted-file envelope used by file protection. */
final class ShieldCrypto {
    static final byte[] FMF1_MAGIC = {'F', 'M', 'F', '1'};
    static final int FMF1_HEADER_SIZE = 20;
    static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private ShieldCrypto() {
    }

    static byte[] gcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    static byte[] gcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    static boolean isFileEncrypted(byte[] blob) {
        return blob != null && blob.length >= FMF1_HEADER_SIZE
                && blob[0] == FMF1_MAGIC[0] && blob[1] == FMF1_MAGIC[1]
                && blob[2] == FMF1_MAGIC[2] && blob[3] == FMF1_MAGIC[3];
    }

    /**
     * FMF1 envelope: magic(4) | version u16 LE | alg u8 | reserved u8 | nonce(12)
     * | ciphertext || GCM tag. AAD is the 20-byte header; the file-domain key is
     * domain-separated from the DEX/policy keys via its HKDF label.
     */
    static byte[] fileEncrypt(byte[] plaintext, byte[] key) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        ByteBuffer header = ByteBuffer.allocate(FMF1_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        header.put(FMF1_MAGIC);
        header.putShort((short) 1);
        header.put((byte) 1);
        header.put((byte) 0);
        header.put(nonce);
        byte[] headerBytes = header.array();
        byte[] ciphertext = gcmEncrypt(key, nonce, plaintext, headerBytes);
        byte[] out = new byte[FMF1_HEADER_SIZE + ciphertext.length];
        System.arraycopy(headerBytes, 0, out, 0, FMF1_HEADER_SIZE);
        System.arraycopy(ciphertext, 0, out, FMF1_HEADER_SIZE, ciphertext.length);
        return out;
    }

    static byte[] fileDecrypt(byte[] blob, byte[] key) throws Exception {
        if (!isFileEncrypted(blob)) {
            throw new IllegalArgumentException("not an FMF1 file");
        }
        ByteBuffer header = ByteBuffer.wrap(blob, 0, FMF1_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        header.getShort(4);
        if (header.get(6) != 1 || header.get(7) != 0) {
            throw new IllegalArgumentException("unsupported FMF1 header");
        }
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 8, nonce, 0, 12);
        byte[] ciphertext = new byte[blob.length - FMF1_HEADER_SIZE];
        System.arraycopy(blob, FMF1_HEADER_SIZE, ciphertext, 0, ciphertext.length);
        return gcmDecrypt(key, nonce, ciphertext,
                java.util.Arrays.copyOfRange(blob, 0, FMF1_HEADER_SIZE));
    }

    static byte[] randomNonce() {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        return nonce;
    }
}
