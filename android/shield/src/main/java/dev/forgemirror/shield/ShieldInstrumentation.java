package dev.forgemirror.shield;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Instrumentation hook for API 26-28 where the pre-created activity callback is
 * unavailable. Installed from ShieldApplication.attachBaseContext; patches the
 * activity base context right before the business onCreate inflates layouts.
 * Untested on a real API 26-28 device; see evidence records.
 */
final class ShieldInstrumentation extends Instrumentation {
    private static final String TAG = "ShieldInstrumentation";

    private ShieldInstrumentation() {
    }

    static void install() {
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            Method current = threadClass.getDeclaredMethod("currentActivityThread");
            current.setAccessible(true);
            Object thread = current.invoke(null);
            Field field = threadClass.getDeclaredField("mInstrumentation");
            field.setAccessible(true);
            field.set(thread, new ShieldInstrumentation());
            Log.i(TAG, "instrumentation installed");
        } catch (Throwable error) {
            Log.w(TAG, "instrumentation install failed", error);
        }
    }

    @Override
    public void callActivityOnCreate(Activity activity, Bundle icicle) {
        ShieldRuntime.adaptActivity(activity);
        super.callActivityOnCreate(activity, icicle);
    }

    @Override
    public void callActivityOnCreate(Activity activity, Bundle icicle,
                                     PersistableBundle persistentState) {
        ShieldRuntime.adaptActivity(activity);
        super.callActivityOnCreate(activity, icicle, persistentState);
    }
}
