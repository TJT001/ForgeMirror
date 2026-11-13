package dev.forgemirror.demo;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

public final class HarnessRemoteService extends Service {
    private static final String TAG = "HarnessRemoteService";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand pid=" + Process.myPid());
        if (intent != null && intent.getBooleanExtra("lock_probe", false)) {
            long start = android.os.SystemClock.elapsedRealtime();
            try (dev.forgemirror.shield.ShieldRandomAccess random =
                         ShieldStorageFacade.openRandomAccessFile(
                                 this, "harness_lock.txt", "rw")) {
                long waited = android.os.SystemClock.elapsedRealtime() - start;
                random.seek(random.length());
                random.write("R".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                Log.i(TAG, "lock probe waitMs=" + waited + " len=" + random.length());
            } catch (Exception error) {
                Log.w(TAG, "lock probe failed: " + error);
            }
        }
        try (dev.forgemirror.shield.ShieldRandomAccess random =
                     ShieldStorageFacade.openRandomAccessFile(
                             this, "harness_ra_renamed.txt", "r")) {
            byte[] sample = new byte[6];
            int read = random.read(sample);
            Log.i(TAG, "remote ra len=" + random.length() + " data="
                    + new String(sample, 0, Math.max(read, 0),
                    java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception error) {
            Log.w(TAG, "remote ra read failed: " + error);
        }
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
