package dev.forgemirror.shield;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class ShieldIntegrity {
    private static final int MAX_MANIFEST_BYTES = 1 << 20;

    private ShieldIntegrity() {
    }

    static void verify(Context context, ShieldConfig config) throws Exception {
        byte[] envelopeBytes = ShieldAssets.read(context, config.manifest);
        if (envelopeBytes.length > MAX_MANIFEST_BYTES) {
            throw new SecurityException("manifest too large");
        }
        JSONObject envelope = new JSONObject(new String(envelopeBytes, java.nio.charset.StandardCharsets.UTF_8));
        String algorithm = envelope.optString("alg");

        byte[] payload = Base64.decode(envelope.getString("payload"), Base64.DEFAULT);
        byte[] signature = Base64.decode(envelope.getString("signature"), Base64.DEFAULT);
        byte[] publicKeyDer = ShieldAssets.read(context, config.trustedKey);

        PublicKey publicKey;
        Signature verifier;
        if ("ecdsa-p256-sha256".equals(algorithm)) {
            publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(publicKeyDer));
            verifier = Signature.getInstance("SHA256withECDSA");
        } else if ("ed25519".equals(algorithm)) {
            publicKey = decodeEd25519(publicKeyDer);
            verifier = newEd25519Verifier();
        } else {
            throw new SecurityException("unsupported manifest algorithm: " + algorithm);
        }

        verifier.initVerify(publicKey);
        verifier.update(payload);
        if (!verifier.verify(signature)) {
            throw new SecurityException("manifest signature invalid");
        }

        JSONObject manifest = new JSONObject(new String(payload, java.nio.charset.StandardCharsets.UTF_8));
        verifyArtifacts(context, manifest);
    }

    private static PublicKey decodeEd25519(byte[] der) throws Exception {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception first) {
            return KeyFactory.getInstance("EdDSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        }
    }

    private static Signature newEd25519Verifier() throws Exception {
        try {
            return Signature.getInstance("Ed25519");
        } catch (Exception first) {
            return Signature.getInstance("EdDSA");
        }
    }

    private static void verifyArtifacts(Context context, JSONObject manifest) throws Exception {
        JSONArray artifacts = manifest.getJSONArray("artifacts");
        String apkPath = context.getApplicationInfo().sourceDir;
        try (ZipFile apk = new ZipFile(apkPath)) {
            for (int index = 0; index < artifacts.length(); index++) {
                JSONObject artifact = artifacts.getJSONObject(index);
                String path = artifact.getString("path");
                long size = artifact.getLong("size");
                String expected = artifact.getString("sha256").toLowerCase(Locale.US);

                ZipEntry entry = apk.getEntry(path);
                if (entry == null) {
                    throw new SecurityException("missing artifact: " + path);
                }
                if (entry.getSize() != size) {
                    throw new SecurityException("artifact size mismatch: " + path);
                }
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                try (InputStream stream = apk.getInputStream(entry)) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = stream.read(buffer)) != -1) {
                        digest.update(buffer, 0, read);
                    }
                }
                String actual = hex(digest.digest());
                if (!MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                    throw new SecurityException("artifact hash mismatch: " + path);
                }
            }
        }
    }

    private static String hex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte item : value) {
            builder.append(String.format(Locale.US, "%02x", item & 0xff));
        }
        return builder.toString();
    }
}
