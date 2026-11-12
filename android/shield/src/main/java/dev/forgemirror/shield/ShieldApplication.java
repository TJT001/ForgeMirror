package dev.forgemirror.shield;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.util.Log;

import java.lang.reflect.Method;

public final class ShieldApplication extends Application {
    private static final String TAG = "ShieldApplication";

    private Application original;
    private boolean originalAttached;
    private boolean originalCreated;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        int state = ShieldRuntime.bootstrap(this);
        Log.i(TAG, "attachBaseContext state=" + state);

        if (state == ShieldRuntime.STATE_RECOVERY) {
            return;
        }
        attachOriginal(base);
    }

    private void attachOriginal(Context base) {
        ShieldConfig config = ShieldRuntime.getConfig();
        if (config == null || config.originalApplication.isEmpty()
                || config.originalApplication.equals(getClass().getName())) {
            return;
        }
        try {
            Class<?> type = Class.forName(config.originalApplication, true, getClassLoader());
            original = (Application) type.getDeclaredConstructor().newInstance();
            Method attach = ContextWrapper.class.getDeclaredMethod("attachBaseContext", Context.class);
            attach.setAccessible(true);
            attach.invoke(original, base);
            originalAttached = true;
            Log.i(TAG, "original Application attached: " + config.originalApplication);
        } catch (Throwable error) {
            Log.e(TAG, "original Application attach failed", error);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (ShieldRuntime.isRecovery()) {
            startRecovery();
            return;
        }
        if (original != null && originalAttached && !originalCreated) {
            originalCreated = true;
            try {
                original.onCreate();
                Log.i(TAG, "original Application onCreate");
            } catch (Throwable error) {
                Log.e(TAG, "original Application onCreate failed", error);
            }
        }
        ShieldRuntime.markRunning();
    }

    private void startRecovery() {
        Log.e(TAG, "entering recovery: " + ShieldRuntime.getFailure());
        try {
            Intent intent = new Intent(this, ShieldRecoveryActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(intent);
        } catch (Throwable error) {
            Log.e(TAG, "recovery activity start failed", error);
        }
    }
}
