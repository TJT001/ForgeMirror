package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** Cached server-side settings; only log/toast responses are accepted. */
final class ShieldServerConfig {
    private static final String TAG = "ShieldServerConfig";
    private static final String FILE = "shield/server_config.json";

    private ShieldServerConfig() {
    }

    static boolean detectionEnabled(Context context, boolean fallback) {
        return read(context).optBoolean("detection", fallback);
    }

    static String response(Context context, String fallback) {
        String value = read(context).optString("response", fallback);
        if ("log".equals(value) || "toast".equals(value)) {
            return value;
        }
        return fallback;
    }

    static String responseFor(Context context, String ruleId, String fallback) {
        JSONObject policies = read(context).optJSONObject("policies");
        if (policies != null && ruleId != null) {
            String value = policies.optString(ruleId, "");
            if ("log".equals(value) || "toast".equals(value)) {
                return value;
            }
        }
        return response(context, fallback);
    }

    static void store(Context context, JSONObject config) {
        try {
            File file = new File(context.getFilesDir(), FILE);
            File parent = file.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                return;
            }
            File temp = new File(parent, file.getName() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(temp)) {
                out.write(config.toString().getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            if (!temp.renameTo(file)) {
                Log.w(TAG, "server config rename failed");
            }
        } catch (Exception error) {
            Log.w(TAG, "server config store failed: " + error);
        }
    }

    private static JSONObject read(Context context) {
        File file = new File(context.getFilesDir(), FILE);
        if (!file.isFile()) {
            return new JSONObject();
        }
        try {
            byte[] data = new byte[(int) file.length()];
            try (FileInputStream in = new FileInputStream(file)) {
                int offset = 0;
                while (offset < data.length) {
                    int read = in.read(data, offset, data.length - offset);
                    if (read < 0) {
                        break;
                    }
                    offset += read;
                }
            }
            return new JSONObject(new String(data, StandardCharsets.UTF_8));
        } catch (Exception error) {
            return new JSONObject();
        }
    }
}
