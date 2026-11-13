package dev.forgemirror.shield;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.time.OffsetDateTime;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Dev authorization client. Registers an RSA Keystore identity, answers a
 * server challenge, and unwraps the build content key. Grants are cached for
 * offline starts until their expiry.
 */
final class ShieldAuthClient {
    private static final String TAG = "ShieldAuth";
    private static final String ALIAS = "forgemirror-device";
    private static final String CACHE = "shield_auth";
    private static final String KEY_GRANT = "grant";
    private static final int TIMEOUT_MS = 10000;

    private ShieldAuthClient() {
    }

    static byte[] fetchContentKey(Context context, ShieldConfig config) throws Exception {
        final Object[] result = new Object[2];
        Thread worker = new Thread(() -> {
            try {
                result[0] = fetchContentKeyBlocking(context, config);
            } catch (Throwable error) {
                result[1] = error;
            }
        }, "shield-auth");
        worker.setDaemon(true);
        worker.start();
        worker.join(20000);
        if (worker.isAlive()) {
            throw new IllegalStateException("dev authorization timed out");
        }
        if (result[1] != null) {
            if (result[1] instanceof Exception) {
                throw (Exception) result[1];
            }
            throw new IllegalStateException(String.valueOf(result[1]));
        }
        return (byte[]) result[0];
    }

    private static byte[] fetchContentKeyBlocking(Context context, ShieldConfig config)
            throws Exception {
        String cacheKey = KEY_GRANT + ":" + config.buildId;
        JSONObject cached = readCache(context, cacheKey);
        if (cached != null && !isExpired(cached)) {
            try {
                Log.i(TAG, "using cached grant " + cached.optString("grant_id"));
                return unwrap(config, cached);
            } catch (Throwable error) {
                Log.w(TAG, "cached grant unusable: " + error);
            }
        }

        try {
            KeyStore.Entry entry = identity();
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
            String deviceId = deviceId(publicKey);
            Log.i(TAG, "device identity " + deviceId);

            JSONObject challenge = post(config.authUrl + "/api/v1/auth/devices",
                    new JSONObject()
                            .put("device_id", deviceId)
                            .put("public_key", Base64.encodeToString(
                                    publicKey.getEncoded(), Base64.NO_WRAP)));
            byte[] nonce = Base64.decode(challenge.getString("nonce"), Base64.NO_WRAP);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(nonce);
            byte[] signature = signer.sign();

            JSONObject grant = post(config.authUrl + "/api/v1/auth/grants",
                    new JSONObject()
                            .put("device_id", deviceId)
                            .put("challenge_id", challenge.getString("challenge_id"))
                            .put("task_id", config.buildId)
                            .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP)));
            grant.put("device_id", deviceId);
            writeCache(context, cacheKey, grant);
            Log.i(TAG, "grant issued " + grant.optString("grant_id"));
            return unwrap(config, grant);
        } catch (Throwable error) {
            if (cached != null && !isExpired(cached)) {
                Log.w(TAG, "network auth failed, using cached grant: " + error);
                return unwrap(config, cached);
            }
            throw error;
        }
    }

    private static byte[] unwrap(ShieldConfig config, JSONObject grant) throws Exception {
        String deviceId = grant.getString("device_id");
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) identity()).getPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        byte[] payload = cipher.doFinal(
                Base64.decode(grant.getString("wrapped_key"), Base64.NO_WRAP));

        JSONObject envelope = new JSONObject(new String(payload, StandardCharsets.UTF_8));
        if (!config.buildId.equals(envelope.getString("task_id"))
                || !deviceId.equals(envelope.getString("device_id"))) {
            throw new SecurityException("grant binding mismatch");
        }
        byte[] key = Base64.decode(envelope.getString("key"), Base64.NO_WRAP);
        if (key.length != 32) {
            throw new SecurityException("unexpected content key length");
        }
        return key;
    }

    private static KeyStore.Entry identity() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setKeySize(3072)
                    .build());
            generator.generateKeyPair();
            Log.i(TAG, "generated Keystore identity");
        }
        return keyStore.getEntry(ALIAS, null);
    }

    private static String deviceId(PublicKey publicKey) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());
        StringBuilder builder = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            builder.append(String.format(Locale.US, "%02x", item & 0xff));
        }
        return builder.toString();
    }

    private static JSONObject post(String url, JSONObject body) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(TIMEOUT_MS);
        connection.setReadTimeout(TIMEOUT_MS);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);
        try (OutputStream out = connection.getOutputStream()) {
            out.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 400
                ? connection.getErrorStream() : connection.getInputStream();
        String text = readAll(stream);
        if (status >= 400) {
            throw new IllegalStateException("auth HTTP " + status + ": " + text);
        }
        return new JSONObject(text);
    }

    private static String readAll(InputStream stream) throws Exception {
        if (stream == null) {
            return "";
        }
        try (InputStream in = stream) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = in.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
            return buffer.toString("UTF-8");
        }
    }

    private static JSONObject readCache(Context context, String key) {
        try {
            String value = context.getSharedPreferences(CACHE, Context.MODE_PRIVATE)
                    .getString(key, null);
            return value == null ? null : new JSONObject(value);
        } catch (Throwable error) {
            return null;
        }
    }

    private static void writeCache(Context context, String key, JSONObject grant) {
        try {
            context.getSharedPreferences(CACHE, Context.MODE_PRIVATE)
                    .edit()
                    .putString(key, grant.toString())
                    .apply();
        } catch (Throwable error) {
            Log.w(TAG, "cache write failed", error);
        }
    }

    private static boolean isExpired(JSONObject grant) {
        try {
            OffsetDateTime expires =
                    OffsetDateTime.parse(grant.getString("expires_at"));
            return expires.toInstant().isBefore(java.time.Instant.now());
        } catch (Throwable error) {
            return true;
        }
    }
}
