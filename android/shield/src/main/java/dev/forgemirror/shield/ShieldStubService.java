package dev.forgemirror.shield;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public final class ShieldStubService extends Service {
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i("ShieldStub", "service gated");
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
