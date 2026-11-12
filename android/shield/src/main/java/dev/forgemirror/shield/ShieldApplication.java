package dev.forgemirror.shield;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
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
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            ShieldInstrumentation.install();
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
            ClassLoader loader = ShieldRuntime.getClassLoader();
            if (loader == null) {
                loader = getClassLoader();
            }
            Class<?> type = Class.forName(config.originalApplication, true, loader);
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
            installOriginalApplication();
            try {
                original.onCreate();
                Log.i(TAG, "original Application onCreate");
            } catch (Throwable error) {
                Log.e(TAG, "original Application onCreate failed", error);
            }
        }
        ShieldRuntime.markRunning();
    }

    /**
     * Make the framework report the original Application from getApplication()
     * and getApplicationContext() by swapping ActivityThread.mInitialApplication
     * and LoadedApk.mApplication after handleBindApplication installed this
     * wrapper as both. Business code casting getApplication() then succeeds.
     */
    private void installOriginalApplication() {
        try {
            Class<?> threadClass = Class.forName("android.app.ActivityThread");
            java.lang.reflect.Method current =
                    threadClass.getDeclaredMethod("currentActivityThread");
            current.setAccessible(true);
            Object thread = current.invoke(null);
            java.lang.reflect.Field initialField =
                    threadClass.getDeclaredField("mInitialApplication");
            initialField.setAccessible(true);
            initialField.set(thread, original);

            Object base = getBaseContext();
            java.lang.reflect.Field packageInfoField =
                    base.getClass().getDeclaredField("mPackageInfo");
            packageInfoField.setAccessible(true);
            Object loadedApk = packageInfoField.get(base);
            java.lang.reflect.Field appField = loadedApk.getClass()
                    .getDeclaredField("mApplication");
            appField.setAccessible(true);
            appField.set(loadedApk, original);

            // After the swap the framework dispatches lifecycle callbacks to the
            // original application only; register the adapter there as well.
            registerActivityAdapter();
            Log.i(TAG, "original Application installed: " + original.getClass().getName());
        } catch (Throwable error) {
            Log.w(TAG, "original Application swap failed; getApplication() stays shield", error);
        }
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

    private void registerActivityAdapter() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return;
        }
        // Register on the original application: after the swap the framework
        // dispatches lifecycle callbacks there, not on this wrapper.
        Application target = original != null ? original : this;
        target.registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            @Override
            public void onActivityPreCreated(Activity activity, Bundle savedInstanceState) {
                ShieldRuntime.adaptActivity(activity);
            }

            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                // Fallback for cases where pre-created dispatch was missed.
                ShieldRuntime.adaptActivity(activity);
            }

            @Override
            public void onActivityStarted(Activity activity) {
            }

            @Override
            public void onActivityResumed(Activity activity) {
            }

            @Override
            public void onActivityPaused(Activity activity) {
            }

            @Override
            public void onActivityStopped(Activity activity) {
            }

            @Override
            public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            }

            @Override
            public void onActivityDestroyed(Activity activity) {
            }
        });
    }
}
