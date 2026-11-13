package dev.forgemirror.shield;

import android.app.Activity;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.util.concurrent.atomic.AtomicBoolean;

/** P1-C5 startup metrics: bootstrap, first-frame approximation, decrypt, RSS. */
final class ShieldMetrics {
    private static final String TAG = "ShieldMetrics";
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static final AtomicBoolean FRAME = new AtomicBoolean();
    private static volatile long startedAt;
    private static volatile long bootstrapMs = -1;
    private static volatile long firstFrameMs = -1;

    private ShieldMetrics() {
    }

    static void start() {
        if (STARTED.compareAndSet(false, true)) {
            startedAt = SystemClock.elapsedRealtime();
        }
    }

    static void bootstrapDone() {
        if (STARTED.get() && bootstrapMs < 0) {
            bootstrapMs = SystemClock.elapsedRealtime() - startedAt;
            Log.i(TAG, "bootstrapMs=" + bootstrapMs);
        }
    }

    static void watchFirstFrame(Activity activity) {
        if (activity == null || FRAME.get()) {
            return;
        }
        activity.getWindow().getDecorView().post(() -> {
            if (!FRAME.compareAndSet(false, true)) {
                return;
            }
            long processStart = Process.getStartElapsedRealtime();
            firstFrameMs = SystemClock.elapsedRealtime() - processStart;
            Log.i(TAG, "firstFrameMs=" + firstFrameMs);
        });
    }

    static String describe() {
        return "metrics bootstrapMs=" + bootstrapMs
                + " firstFrameMs=" + firstFrameMs;
    }
}
