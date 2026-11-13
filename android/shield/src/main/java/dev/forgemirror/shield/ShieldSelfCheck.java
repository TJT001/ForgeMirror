package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** Verifies that shell native libraries are mapped from the installed APK. */
final class ShieldSelfCheck {
    private static final String TAG = "ShieldSelfCheck";
    private static final AtomicBoolean STARTED = new AtomicBoolean();

    private ShieldSelfCheck() {
    }

    static void start(Context context, ShieldConfig config) {
        if (!STARTED.compareAndSet(false, true) || !ShieldProcess.isMain(context)) {
            return;
        }
        Thread thread = new Thread(() -> check(context, config), "shield-self-check");
        thread.setDaemon(true);
        thread.start();
    }

    private static void check(Context context, ShieldConfig config) {
        String sourceDir = context.getApplicationInfo().sourceDir;
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (sourceDir == null || nativeDir == null) {
            return;
        }
        File maps = new File("/proc/self/maps");
        if (!maps.isFile()) {
            return;
        }
        boolean apkMapped = false;
        int shellLibs = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(maps), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String path = pathOf(line);
                if (path == null) {
                    continue;
                }
                if (path.equals(sourceDir)) {
                    apkMapped = true;
                }
                if (!path.contains("libshield") && !path.contains("libshadowhook")) {
                    continue;
                }
                shellLibs++;
                if (path.contains("(deleted)") || !isTrustedPath(path, sourceDir, nativeDir)) {
                    report(context, config, "untrusted:" + path);
                    return;
                }
            }
        } catch (Exception error) {
            Log.w(TAG, "self check failed: " + error);
            return;
        }
        if (!apkMapped) {
            report(context, config, "apkMapped=false");
            return;
        }
        Log.i(TAG, "self check ok shellLibs=" + shellLibs);
    }

    static boolean isTrustedPath(String path, String sourceDir, String nativeDir) {
        return path.equals(sourceDir)
                || path.startsWith(sourceDir + "!/lib/")
                || path.startsWith(nativeDir + "/")
                || path.startsWith("/data/app/") && path.contains("/lib/");
    }

    private static void report(Context context, ShieldConfig config, String evidence) {
        Log.w(TAG, "self check report: " + evidence);
        try {
            JSONObject payload = new JSONObject();
            payload.put("evidence", evidence);
            ShieldEvents.record("file_tamper", "self_check", 0.7,
                    sha256(evidence), payload);
        } catch (Exception error) {
            Log.w(TAG, "self check record failed: " + error);
        }
    }

    private static String pathOf(String line) {
        int slash = line.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String path = line.substring(slash).trim();
        return path.isEmpty() ? null : path;
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                builder.append(String.format(Locale.US, "%02x", item & 0xff));
            }
            return builder.toString();
        } catch (Exception error) {
            return "";
        }
    }
}
