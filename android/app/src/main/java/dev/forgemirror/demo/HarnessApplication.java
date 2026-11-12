package dev.forgemirror.demo;

import android.app.Application;
import android.content.Context;
import android.os.Process;
import android.util.Log;

public final class HarnessApplication extends Application {
    private static final String TAG = "HarnessApplication";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.i(TAG, "attachBaseContext pid=" + Process.myPid());
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate pid=" + Process.myPid());
    }
}
