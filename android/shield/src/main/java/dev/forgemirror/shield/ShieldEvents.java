package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Structured security events with a local FMF1-encrypted queue and background
 * batch upload. Events are retained until the server accepts them; the queue is
 * capped and de-duplicated by rule/evidence hash.
 */
final class ShieldEvents {
    private static final String TAG = "ShieldEvents";
    private static final int MAX_EVENTS = 200;
    private static final int MAX_SEEN = 512;
    private static final int TIMEOUT_MS = 8000;
    private static final long BASE_BACKOFF_MS = 1000;
    private static final long MAX_BACKOFF_MS = 5 * 60 * 1000;
    private static final ScheduledExecutorService EXECUTOR =
            Executors.newSingleThreadScheduledExecutor();
    private static final AtomicBoolean FLUSHING = new AtomicBoolean();
    private static final AtomicBoolean SCHEDULED = new AtomicBoolean();
    private static final List<JSONObject> QUEUE = new ArrayList<>();
    private static final java.util.LinkedHashSet<String> SEEN =
            new java.util.LinkedHashSet<>();

    private static Context appContext;
    private static ShieldConfig config;
    private static byte[] key;
    private static File queueFile;
    private static File seenFile;
    private static volatile boolean enabled;
    private static int failures;
    private static long nextAttemptMs;

    private ShieldEvents() {
    }

    static synchronized void init(Context context, ShieldConfig shieldConfig, byte[] fileKey) {
        String processName = processName();
        if (processName != null && !processName.equals(context.getPackageName())) {
            Log.i(TAG, "disabled in process=" + processName);
            return;
        }
        enabled = true;
        appContext = context.getApplicationContext();
        if (appContext == null) {
            appContext = context;
        }
        config = shieldConfig;
        key = fileKey;
        queueFile = new File(context.getFilesDir(), "shield/events.fmf");
        seenFile = new File(context.getFilesDir(), "shield/events.seen.fmf");
        loadLocked();
        loadSeenLocked();
        for (JSONObject event : QUEUE) {
            rememberLocked(event.isNull("rule_id") ? null : event.optString("rule_id"),
                    event.isNull("evidence_hash") ? null : event.optString("evidence_hash"),
                    false);
        }
        Log.i(TAG, "init url=" + (shieldConfig.eventUrl == null ? "null" : shieldConfig.eventUrl)
                + " keyLen=" + (fileKey == null ? 0 : fileKey.length)
                + " queued=" + QUEUE.size()
                + " cleartext=" + android.security.NetworkSecurityPolicy.getInstance()
                        .isCleartextTrafficPermitted("127.0.0.1")
                + " loader=" + ShieldEvents.class.getClassLoader()
                + " app=" + (appContext == null ? "null" : appContext.getPackageName()));
        if (!QUEUE.isEmpty()) {
            scheduleFlush();
        }
    }

    private static String processName() {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 28) {
                return android.app.Application.getProcessName();
            }
            byte[] raw = new byte[256];
            try (java.io.FileInputStream in =
                         new java.io.FileInputStream("/proc/self/cmdline")) {
                int length = in.read(raw);
                if (length > 0) {
                    int end = 0;
                    while (end < length && raw[end] != 0) {
                        end++;
                    }
                    return new String(raw, 0, end, StandardCharsets.UTF_8);
                }
            }
        } catch (Throwable error) {
            Log.w(TAG, "process name unavailable: " + error);
        }
        return null;
    }

    static void record(String kind, String ruleId, double confidence,
                       String evidenceHash, JSONObject payload) {
        if (!enabled) {
            return;
        }
        synchronized (ShieldEvents.class) {
            if (key == null || appContext == null) {
                Log.w(TAG, "record skipped: key=" + (key == null ? "null" : "set")
                        + " app=" + (appContext == null ? "null" : "set")
                        + " loader=" + ShieldEvents.class.getClassLoader());
                return;
            }
            String dedupeKey = seenKey(ruleId, evidenceHash);
            if (dedupeKey != null && SEEN.contains(dedupeKey)) {
                scheduleFlush();
                return;
            }
            try {
                JSONObject event = new JSONObject();
                event.put("id", java.util.UUID.randomUUID().toString());
                event.put("kind", kind);
                event.put("rule_id", ruleId);
                event.put("confidence", confidence);
                event.put("evidence_hash", evidenceHash);
                event.put("ts", Instant.now().toString());
                event.put("payload", payload == null ? new JSONObject() : payload);
                QUEUE.add(event);
                while (QUEUE.size() > MAX_EVENTS) {
                    QUEUE.remove(0);
                }
                rememberLocked(ruleId, evidenceHash, true);
                persistLocked();
                Log.i(TAG, "recorded " + kind + "/" + ruleId + " queued=" + QUEUE.size());
            } catch (Exception error) {
                Log.w(TAG, "event record failed: " + error);
            }
        }
        scheduleFlush();
    }

    private static void scheduleFlush() {
        if (config == null || config.eventUrl == null || config.eventUrl.isEmpty()) {
            return;
        }
        long delay;
        synchronized (ShieldEvents.class) {
            if (QUEUE.isEmpty()) {
                return;
            }
            delay = Math.max(0, nextAttemptMs - android.os.SystemClock.elapsedRealtime());
        }
        if (!SCHEDULED.compareAndSet(false, true)) {
            return;
        }
        EXECUTOR.schedule(() -> {
            SCHEDULED.set(false);
            flush();
        }, delay, TimeUnit.MILLISECONDS);
    }

    private static void flush() {
        if (!FLUSHING.compareAndSet(false, true)) {
            return;
        }
        boolean failed = false;
        try {
            List<JSONObject> snapshot;
            String packageName;
            String url;
            String token;
            synchronized (ShieldEvents.class) {
                if (QUEUE.isEmpty() || config == null
                        || config.eventUrl == null || config.eventUrl.isEmpty()) {
                    return;
                }
                snapshot = new ArrayList<>(QUEUE);
                packageName = appContext.getPackageName();
                url = config.eventUrl + "/api/v1/events";
                token = config.eventToken;
            }
            JSONArray events = new JSONArray();
            for (JSONObject event : snapshot) {
                events.put(event);
            }
            JSONObject body = new JSONObject();
            body.put("app_package", packageName);
            body.put("device_id", "");
            body.put("events", events);
            Log.i(TAG, "flushing " + snapshot.size() + " events to " + url);
            if (!post(url, token, body)) {
                failed = true;
                return;
            }
            Log.i(TAG, "flushed " + snapshot.size() + " events");
            synchronized (ShieldEvents.class) {
                List<String> sent = new ArrayList<>();
                for (JSONObject event : snapshot) {
                    sent.add(event.optString("id"));
                }
                for (Iterator<JSONObject> iterator = QUEUE.iterator(); iterator.hasNext(); ) {
                    JSONObject event = iterator.next();
                    if (sent.contains(event.optString("id"))) {
                        iterator.remove();
                    }
                }
                failures = 0;
                nextAttemptMs = 0;
                persistLocked();
            }
        } catch (Exception error) {
            failed = true;
            Log.w(TAG, "event flush failed: " + error);
        } finally {
            FLUSHING.set(false);
            if (failed) {
                synchronized (ShieldEvents.class) {
                    failures = Math.min(failures + 1, 10);
                    long backoff = BASE_BACKOFF_MS << Math.min(failures - 1, 8);
                    nextAttemptMs = android.os.SystemClock.elapsedRealtime()
                            + Math.min(backoff, MAX_BACKOFF_MS);
                    Log.w(TAG, "upload retry scheduled failures=" + failures
                            + " inMs=" + Math.min(backoff, MAX_BACKOFF_MS));
                }
                scheduleFlush();
            } else {
                boolean remaining;
                synchronized (ShieldEvents.class) {
                    remaining = !QUEUE.isEmpty();
                }
                if (remaining) {
                    scheduleFlush();
                }
            }
        }
    }

    private static boolean post(String url, String token, JSONObject body) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            if (token != null && !token.isEmpty()) {
                connection.setRequestProperty("X-Client-Token", token);
            }
            connection.setDoOutput(true);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body.toString().getBytes(StandardCharsets.UTF_8));
            }
            int status = connection.getResponseCode();
            if (status < 200 || status >= 300) {
                String detail = readAll(connection.getErrorStream());
                Log.w(TAG, "event upload HTTP " + status + ": " + detail);
                return false;
            }
            return true;
        } catch (Exception error) {
            Log.w(TAG, "event upload failed: " + error);
            return false;
        }
    }

    private static String readAll(InputStream stream) {
        if (stream == null) {
            return "";
        }
        try (InputStream input = stream) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = input.read(chunk)) != -1) {
                output.write(chunk, 0, read);
            }
            return output.toString("UTF-8");
        } catch (Exception error) {
            return "";
        }
    }

    private static String seenKey(String ruleId, String evidenceHash) {
        if (ruleId == null || evidenceHash == null || evidenceHash.isEmpty()) {
            return null;
        }
        return ruleId + "|" + evidenceHash;
    }

    private static void rememberLocked(String ruleId, String evidenceHash, boolean persist) {
        String seenKey = seenKey(ruleId, evidenceHash);
        if (seenKey == null) {
            return;
        }
        SEEN.remove(seenKey);
        SEEN.add(seenKey);
        while (SEEN.size() > MAX_SEEN) {
            Iterator<String> iterator = SEEN.iterator();
            iterator.next();
            iterator.remove();
        }
        if (persist) {
            persistSeenLocked();
        }
    }

    private static void loadSeenLocked() {
        if (seenFile == null || !seenFile.isFile()) {
            return;
        }
        try {
            byte[] blob = readFile(seenFile);
            byte[] plaintext = ShieldCrypto.isFileEncrypted(blob)
                    ? ShieldCrypto.fileDecrypt(blob, key) : blob;
            JSONArray array = new JSONArray(new String(plaintext, StandardCharsets.UTF_8));
            for (int index = 0; index < array.length(); index++) {
                String item = array.optString(index, "");
                if (!item.isEmpty()) {
                    SEEN.remove(item);
                    SEEN.add(item);
                }
            }
            while (SEEN.size() > MAX_SEEN) {
                Iterator<String> iterator = SEEN.iterator();
                iterator.next();
                iterator.remove();
            }
        } catch (Exception error) {
            Log.w(TAG, "event seen load failed: " + error);
            SEEN.clear();
        }
    }

    private static void persistSeenLocked() {
        if (seenFile == null || key == null) {
            return;
        }
        try {
            JSONArray array = new JSONArray();
            for (String item : SEEN) {
                array.put(item);
            }
            byte[] blob = ShieldCrypto.fileEncrypt(
                    array.toString().getBytes(StandardCharsets.UTF_8), key);
            writeAtomic(seenFile, blob);
        } catch (Exception error) {
            Log.w(TAG, "event seen persist failed: " + error);
        }
    }

    private static byte[] readFile(File file) throws Exception {
        byte[] blob = new byte[(int) file.length()];
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            int offset = 0;
            while (offset < blob.length) {
                int read = in.read(blob, offset, blob.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        }
        return blob;
    }

    private static void writeAtomic(File file, byte[] blob) throws Exception {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new java.io.IOException("cannot create " + parent);
        }
        File temp = new File(parent, file.getName() + ".tmp");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(temp)) {
            out.write(blob);
            out.getFD().sync();
        }
        if (!temp.renameTo(file)) {
            throw new java.io.IOException("rename failed: " + file);
        }
    }

    private static void loadLocked() {
        if (queueFile == null || !queueFile.isFile()) {
            return;
        }
        try {
            byte[] blob = new byte[(int) queueFile.length()];
            try (java.io.FileInputStream in = new java.io.FileInputStream(queueFile)) {
                int offset = 0;
                while (offset < blob.length) {
                    int read = in.read(blob, offset, blob.length - offset);
                    if (read < 0) {
                        break;
                    }
                    offset += read;
                }
            }
            byte[] plaintext = ShieldCrypto.isFileEncrypted(blob)
                    ? ShieldCrypto.fileDecrypt(blob, key) : blob;
            JSONArray array = new JSONArray(new String(plaintext, StandardCharsets.UTF_8));
            for (int index = 0; index < array.length(); index++) {
                QUEUE.add(array.getJSONObject(index));
            }
        } catch (Exception error) {
            Log.w(TAG, "event queue load failed: " + error);
            QUEUE.clear();
        }
    }

    private static void persistLocked() {
        if (queueFile == null || key == null) {
            return;
        }
        try {
            JSONArray array = new JSONArray();
            for (JSONObject event : QUEUE) {
                array.put(event);
            }
            byte[] blob = ShieldCrypto.fileEncrypt(
                    array.toString().getBytes(StandardCharsets.UTF_8), key);
            File parent = queueFile.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                return;
            }
            File temp = new File(parent, queueFile.getName() + ".tmp");
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(temp)) {
                out.write(blob);
                out.getFD().sync();
            }
            if (!temp.renameTo(queueFile)) {
                Log.w(TAG, "event queue rename failed");
            }
        } catch (Exception error) {
            Log.w(TAG, "event queue persist failed: " + error);
        }
    }
}
