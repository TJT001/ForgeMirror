package dev.forgemirror.shield;

import android.content.Context;
import android.os.FileObserver;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Watches the shell state directory for deletion/move/attribute changes.
 * Temporary files written by the queue/updater are ignored; a real delete or
 * move produces a file_tamper event and the configured response.
 */
final class ShieldFileWatch {
    private static final String TAG = "ShieldFileWatch";
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static final List<FileObserver> observers = new ArrayList<>();

    private ShieldFileWatch() {
    }

    static void start(Context context, ShieldConfig config) {
        if (!STARTED.compareAndSet(false, true) || !ShieldProcess.isMain(context)) {
            return;
        }
        File dir = new File(context.getFilesDir(), "shield");
        if (!dir.isDirectory() && !dir.mkdirs()) {
            Log.w(TAG, "cannot create " + dir);
            return;
        }
        watchTree(context, config, dir, 0);
        File filesDir = context.getFilesDir();
        if (filesDir != null && filesDir.isDirectory()) {
            FileObserver parent = new FileObserver(filesDir.getAbsolutePath(),
                    FileObserver.DELETE | FileObserver.MOVED_FROM
                            | FileObserver.DELETE_SELF | FileObserver.MOVE_SELF) {
                @Override
                public void onEvent(int event, String path) {
                    if ("shield".equals(path)) {
                        handle(context, config, event, "shield");
                    }
                }
            };
            parent.startWatching();
            observers.add(parent);
        }
        Log.i(TAG, "watching " + dir);
    }

    private static void watchTree(Context context, ShieldConfig config, File dir, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 4) {
            return;
        }
        FileObserver watcher = new FileObserver(dir.getAbsolutePath(),
                FileObserver.DELETE | FileObserver.MOVED_FROM
                        | FileObserver.DELETE_SELF | FileObserver.MOVE_SELF
                        | FileObserver.ATTRIB) {
            @Override
            public void onEvent(int event, String path) {
                handle(context, config, event, path);
            }
        };
        watcher.startWatching();
        observers.add(watcher);
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                watchTree(context, config, child, depth + 1);
            }
        }
    }

    private static void handle(Context context, ShieldConfig config, int event, String path) {
        if (path != null && (path.endsWith(".tmp") || path.endsWith(".lock"))) {
            return;
        }
        String operation;
        if ((event & FileObserver.DELETE) != 0) {
            operation = "delete";
        } else if ((event & FileObserver.MOVED_FROM) != 0) {
            operation = "move";
        } else if ((event & FileObserver.ATTRIB) != 0) {
            operation = "attrib";
        } else if ((event & FileObserver.DELETE_SELF) != 0) {
            operation = "delete_self";
        } else if ((event & FileObserver.MOVE_SELF) != 0) {
            operation = "move_self";
        } else {
            return;
        }
        String target = path == null ? "shield" : path;
        String evidence = operation + ":" + target;
        Log.w(TAG, "tamper " + evidence);
        try {
            JSONObject payload = new JSONObject();
            payload.put("operation", operation);
            payload.put("path", target);
            ShieldEvents.record("file_tamper", "file_" + operation, 0.8,
                    sha256(evidence), payload);
        } catch (Exception error) {
            Log.w(TAG, "tamper record failed: " + error);
        }
        List<ShieldDetect.Finding> findings = new ArrayList<>();
        findings.add(new ShieldDetect.Finding("file_tamper", "tamper", target, 0.8));
        ShieldResponse.dispatch(context, findings,
                ShieldServerConfig.response(context, config.response));
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
