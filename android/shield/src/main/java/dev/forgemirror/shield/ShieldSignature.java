package dev.forgemirror.shield;

import android.content.Context;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** Detached signature verification used by policy and rule packages. */
final class ShieldSignature {
    static final int SIG_ED25519 = 1;
    static final int SIG_ECDSA_P256_RAW = 2;

    private ShieldSignature() {
    }

    static void verify(Context context, ShieldConfig config, int sigAlg,
                       byte[] signature, byte[] body) throws Exception {
        byte[] keyDer = ShieldAssets.read(context, config.trustedKey);
        if (sigAlg == SIG_ECDSA_P256_RAW) {
            PublicKey publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(keyDer));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(body);
            if (!verifier.verify(derFromRaw(signature))) {
                throw new SecurityException("signature invalid");
            }
        } else if (sigAlg == SIG_ED25519) {
            PublicKey publicKey;
            try {
                publicKey = KeyFactory.getInstance("Ed25519")
                        .generatePublic(new X509EncodedKeySpec(keyDer));
            } catch (Exception unavailable) {
                publicKey = KeyFactory.getInstance("EdDSA")
                        .generatePublic(new X509EncodedKeySpec(keyDer));
            }
            Signature verifier;
            try {
                verifier = Signature.getInstance("Ed25519");
            } catch (Exception unavailable) {
                verifier = Signature.getInstance("EdDSA");
            }
            verifier.initVerify(publicKey);
            verifier.update(body);
            if (!verifier.verify(signature)) {
                throw new SecurityException("signature invalid");
            }
        } else {
            throw new SecurityException("unsupported signature id " + sigAlg);
        }
    }

    /** Convert a raw r||s 64-byte ECDSA signature into DER for JCA verification. */
    private static byte[] derFromRaw(byte[] raw) {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64)).toByteArray();
        int length = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + length];
        der[0] = 0x30;
        der[1] = (byte) length;
        der[2] = 0x02;
        der[3] = (byte) r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        der[4 + r.length] = 0x02;
        der[5 + r.length] = (byte) s.length;
        System.arraycopy(s, 0, der, 6 + r.length, s.length);
        return der;
    }
}
