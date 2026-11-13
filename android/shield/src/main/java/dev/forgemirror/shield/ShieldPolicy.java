package dev.forgemirror.shield;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/** SPK1 policy package: parse, authenticate, and match file paths. */
final class ShieldPolicy {
    private static final byte[] MAGIC = {'S', 'P', 'K', '1'};
    private static final int HEADER_SIZE = 24;
    private static final int TAG_SIZE = 16;
    private static final int SIGNATURE_SIZE = 64;
    private static final int SIG_ED25519 = 1;
    private static final int SIG_ECDSA_P256_RAW = 2;
    private static final byte[] POLICY_LABEL =
            "FM/policy/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] FILE_LABEL =
            "FM/files/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private final List<Pattern> rules = new ArrayList<>();
    private final List<Pattern> excludes = new ArrayList<>();

    private ShieldPolicy() {
    }

    static ShieldPolicy load(Context context, ShieldConfig config, byte[] kContent)
            throws Exception {
        if (config.policy == null || config.policy.isEmpty() || kContent == null) {
            return null;
        }
        byte[] pkg;
        try {
            pkg = ShieldAssets.read(context, config.policy);
        } catch (Exception missing) {
            return null;
        }

        if (pkg.length < HEADER_SIZE + TAG_SIZE + SIGNATURE_SIZE
                || pkg[0] != MAGIC[0] || pkg[1] != MAGIC[1]
                || pkg[2] != MAGIC[2] || pkg[3] != MAGIC[3]) {
            throw new SecurityException("bad policy package header");
        }
        ByteBuffer header = ByteBuffer.wrap(pkg, 0, HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        int version = Short.toUnsignedInt(header.getShort(4));
        int cipher = header.get(6) & 0xff;
        int sigAlg = header.get(7) & 0xff;
        int plaintextLen = header.getInt(20);
        if (version != 1 || cipher != 1) {
            throw new SecurityException("unsupported policy package");
        }
        if (pkg.length != HEADER_SIZE + plaintextLen + TAG_SIZE + SIGNATURE_SIZE) {
            throw new SecurityException("policy package length mismatch");
        }

        byte[] signature = Arrays.copyOfRange(
                pkg, pkg.length - SIGNATURE_SIZE, pkg.length);
        byte[] body = Arrays.copyOfRange(pkg, 0, pkg.length - SIGNATURE_SIZE);
        verifyPolicySignature(context, config, sigAlg, signature, body);

        byte[] buildId = uuidBytes(config.buildId);
        byte[] key = ShieldCrypto.hkdf(kContent, buildId, POLICY_LABEL);
        byte[] nonce = Arrays.copyOfRange(pkg, 8, 20);
        byte[] ciphertext = Arrays.copyOfRange(
                pkg, HEADER_SIZE, pkg.length - SIGNATURE_SIZE);
        byte[] plaintext = ShieldCrypto.gcmDecrypt(key, nonce, ciphertext,
                Arrays.copyOfRange(pkg, 0, HEADER_SIZE));

        JSONObject json = new JSONObject(
                new String(plaintext, java.nio.charset.StandardCharsets.UTF_8));
        if (!"forgemirror.policy/1".equals(json.optString("schema"))) {
            throw new SecurityException("unsupported policy schema");
        }

        ShieldPolicy policy = new ShieldPolicy();
        for (int index = 0; index < json.optJSONArray("rules").length(); index++) {
            JSONObject rule = json.getJSONArray("rules").getJSONObject(index);
            if ("encrypt".equals(rule.optString("action"))) {
                policy.rules.add(compile(rule.getString("pattern")));
            }
        }
        JSONArray excludeArray = json.optJSONArray("excludes");
        if (excludeArray != null) {
            for (int index = 0; index < excludeArray.length(); index++) {
                policy.excludes.add(
                        compile(excludeArray.getJSONObject(index).getString("pattern")));
            }
        }
        return policy;
    }

    static byte[] uuidBytes(String buildId) {
        if (buildId == null || buildId.isEmpty()) {
            return new byte[16];
        }
        UUID uuid = UUID.fromString(buildId);
        return ByteBuffer.allocate(16)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    static byte[] deriveFileKey(byte[] kContent, String buildId) throws Exception {
        return ShieldCrypto.hkdf(kContent, uuidBytes(buildId), FILE_LABEL);
    }

    boolean encrypts(String relPath) {
        for (Pattern exclude : excludes) {
            if (exclude.matcher(relPath).matches()) {
                return false;
            }
        }
        for (Pattern rule : rules) {
            if (rule.matcher(relPath).matches()) {
                return true;
            }
        }
        return false;
    }

    private static void verifyPolicySignature(
            Context context, ShieldConfig config, int sigAlg,
            byte[] signature, byte[] body) throws Exception {
        byte[] keyDer = ShieldAssets.read(context, config.trustedKey);
        if (sigAlg == SIG_ECDSA_P256_RAW) {
            PublicKey publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(keyDer));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(body);
            if (!verifier.verify(derFromRaw(signature))) {
                throw new SecurityException("policy signature invalid");
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
                throw new SecurityException("policy signature invalid");
            }
        } else {
            throw new SecurityException("unsupported policy signature id " + sigAlg);
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

    /**
     * Pattern semantics per docs/formats/policy-v1.md: '*' matches within one
     * path segment, '**' across segments, '?' a single character.
     */
    private static Pattern compile(String pattern) {
        StringBuilder regex = new StringBuilder();
        for (int index = 0; index < pattern.length(); index++) {
            char current = pattern.charAt(index);
            if (current == '*') {
                if (index + 1 < pattern.length() && pattern.charAt(index + 1) == '*') {
                    regex.append(".*");
                    index++;
                } else {
                    regex.append("[^/]*");
                }
            } else if (current == '?') {
                regex.append("[^/]");
            } else {
                regex.append(Pattern.quote(String.valueOf(current)));
            }
        }
        return Pattern.compile("^" + regex + "$");
    }
}
