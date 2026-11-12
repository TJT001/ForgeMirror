package dev.forgemirror.demo;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

public final class HarnessService extends Service {
    private static final String TAG = "HarnessService";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand pid=" + Process.myPid());
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
