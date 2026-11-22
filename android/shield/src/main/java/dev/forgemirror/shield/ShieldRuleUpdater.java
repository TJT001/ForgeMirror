package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Background rule/config refresh. A downloaded PKR1 package is verified with
 * the embedded key and build id before it replaces the remote slot, which is
 * only used from the next process start.
 */
final class ShieldRuleUpdater {
    private static final String TAG = "ShieldRuleUpdater";
    private static final int MAX_RULES_BYTES = 2 << 20;
    private static final int TIMEOUT_MS = 6000;

    private ShieldRuleUpdater() {
    }

    static void start(Context context, ShieldConfig config, byte[] buildId) {
        if (config.eventUrl == null || config.eventUrl.isEmpty() || buildId == null) {
            return;
        }
        if (!ShieldProcess.isMain(context)) {
            return;
        }
        Thread thread = new Thread(() -> update(context, config, buildId),
                "shield-rule-update");
        thread.setDaemon(true);
        thread.start();
    }

    private static void update(Context context, ShieldConfig config, byte[] buildId) {
        try {
            updateConfig(context, config);
        } catch (Exception error) {
            Log.w(TAG, "config update failed: " + error);
        }
        try {
            updateRules(context, config, buildId);
        } catch (Exception error) {
            Log.w(TAG, "rules update failed: " + error);
        }
    }

    private static void updateConfig(Context context, ShieldConfig config)
            throws Exception {
        String url = config.eventUrl + "/api/v1/config?app_package="
                + encode(context.getPackageName()) + "&build_id="
                + encode(config.buildId);
        byte[] body = get(url, config.eventToken, 64 << 10);
        if (body == null) {
            return;
        }
        JSONObject json = new JSONObject(new String(body, StandardCharsets.UTF_8));
        JSONObject safe = new JSONObject();
        safe.put("detection", json.optBoolean("detection", true));
        String response = json.optString("response", "toast");
        safe.put("response", "log".equals(response) ? "log" : "toast");
        JSONObject policies = new JSONObject();
        JSONObject incoming = json.optJSONObject("policies");
        if (incoming != null) {
            java.util.Iterator<String> keys = incoming.keys();
            while (keys.hasNext()) {
                String rule = keys.next();
                if (!knownRule(rule)) {
                    continue;
                }
                String mode = incoming.optString(rule, "");
                if ("log".equals(mode) || "toast".equals(mode) || "block".equals(mode) || "degrade".equals(mode)) {
                    policies.put(rule, mode);
                }
            }
        }
        safe.put("policies", policies);
        ShieldServerConfig.store(context, safe);
        Log.i(TAG, "server config applied response=" + safe.optString("response"));
    }

    private static void updateRules(Context context, ShieldConfig config, byte[] buildId)
            throws Exception {
        int current = ShieldRules.currentVersion(context, config);
        String url = config.eventUrl + "/api/v1/rules/latest?app_package="
                + encode(context.getPackageName()) + "&build_id="
                + encode(config.buildId) + "&current=" + current;
        byte[] body = get(url, config.eventToken, MAX_RULES_BYTES);
        if (body == null || body.length == 0) {
            return;
        }
        ShieldRules parsed = ShieldRules.parsePackage(context, config, buildId, body);
        try {
            if (parsed.version <= current) {
                Log.i(TAG, "remote rules not newer: " + parsed.version);
                return;
            }
            writeAtomic(context, "shield/rules.remote.pkr", body);
            writeAtomic(context, "shield/rules.version",
                    Integer.toString(parsed.version).getBytes(StandardCharsets.UTF_8));
            Log.i(TAG, "remote rules stored version=" + parsed.version);
        } finally {
            parsed.close();
        }
    }

    private static boolean knownRule(String rule) {
        switch (rule) {
            case "env_frida":
            case "env_xposed":
            case "env_injection":
            case "env_unpacker":
            case "env_hook":
            case "env_debugger":
            case "env_root":
            case "env_emulator":
            case "file_tamper":
            case "yidun_root":
            case "yidun_mount":
            case "yidun_debug":
            case "yidun_hook":
            case "yidun_xposed":
            case "yidun_injection":
            case "yidun_emulator":
            case "yidun_ld_preload":
            case "yidun_dex":
            case "yidun_usb_debug":
            case "yidun_vpn":
            case "yidun_mock_location":
            case "yidun_rom":
            case "env_proxy":
            case "env_packet_capture":
            case "env_clone":
            case "env_autotap":
            case "env_screen_share":
                return true;
            default:
                return false;
        }
    }

    private static byte[] get(String url, String token, int limit) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(TIMEOUT_MS);
        connection.setReadTimeout(TIMEOUT_MS);
        connection.setRequestMethod("GET");
        if (token != null && !token.isEmpty()) {
            connection.setRequestProperty("X-Client-Token", token);
        }
        int status = connection.getResponseCode();
        if (status == HttpURLConnection.HTTP_NO_CONTENT
                || status == HttpURLConnection.HTTP_NOT_FOUND) {
            return null;
        }
        if (status < 200 || status >= 300) {
            Log.w(TAG, "HTTP " + status + " for " + url);
            return null;
        }
        try (InputStream input = connection.getInputStream()) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = input.read(chunk)) != -1) {
                if (output.size() + read > limit) {
                    throw new IllegalStateException("response too large");
                }
                output.write(chunk, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static void writeAtomic(Context context, String name, byte[] data)
            throws Exception {
        File file = new File(context.getFilesDir(), name);
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create " + parent);
        }
        File temp = new File(parent, file.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(temp)) {
            out.write(data);
            out.getFD().sync();
        }
        if (!temp.renameTo(file)) {
            throw new IllegalStateException("rename failed: " + file);
        }
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value == null ? "" : value, "UTF-8");
        } catch (Exception error) {
            return "";
        }
    }
}
