package dev.forgemirror.demo;

import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import dev.forgemirror.demo.databinding.ActivityMainBinding;
import dev.forgemirror.shield.ShieldRuntime;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    static {
        System.loadLibrary("demo");
    }

    private ActivityMainBinding binding;
    private boolean servicesStarted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        Log.i(TAG, "onCreate");

        HarnessStorage.exercise(this);
        sendBroadcast(new Intent(this, HarnessReceiver.class).setAction(HarnessReceiver.ACTION));

        String providerStatus = "provider=unavailable";
        try (Cursor cursor = getContentResolver().query(
                HarnessProvider.CONTENT_URI, null, null, null, null)) {
            if (cursor != null) {
                providerStatus = "provider rows=" + cursor.getCount();
            }
        }

        String appStatus = "app=unknown";
        try {
            HarnessApplication app = (HarnessApplication) getApplication();
            appStatus = "app=" + app.getClass().getSimpleName();
        } catch (Throwable error) {
            Log.w(TAG, "getApplication cast failed", error);
            appStatus = "app=cast-failed";
        }

        if (getIntent().getBooleanExtra("demo_toast", false)) {
            ShieldStorageFacade.showDemoToast(this);
        }

        TextView tv = binding.sampleText;
        String probeFile = getFilesDir() + "/harness_ra_renamed.txt";
        int textWriteErr = nativeProbeWriteText(probeFile, "T2XYZ6");
        String nativeText = nativeProbeText(probeFile);
        String javaText = HarnessStorage.readRandomText(this);
        int mmapWriteErr = nativeProbeMmapWrite(probeFile, "M2XYZ6");
        String javaMmap = HarnessStorage.readRandomText(this);
        int dupWriteErr = nativeProbeDupWrite(probeFile, "D2XYZ6");
        String javaDup = HarnessStorage.readRandomText(this);
        nativeProbeHoldWrite(probeFile, "P2XYZ6", 5000);
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        String periodic = HarnessStorage.readRandomText(this);
        nativeProbeWriteText(probeFile, "0Q2XYZ");
        String probe = "probe writeErr=" + nativeProbeWrite(probeFile)
                + " readErr=" + nativeProbeRead(probeFile)
                + " mmapErr=" + nativeProbeMmap(probeFile)
                + " syscallErr=" + nativeProbeSyscall(probeFile)
                + " textErr=" + textWriteErr + " native=" + nativeText
                + " java=" + javaText + " mmapWriteErr=" + mmapWriteErr
                + " javaMmap=" + javaMmap + " periodic=" + periodic
                + " dupErr=" + dupWriteErr + " javaDup=" + javaDup;
        tv.setText(stringFromJNI() + "\n" + appStatus + "\n" + providerStatus
                + "\n" + HarnessStorage.verify(this) + "\n" + probe);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent != null && intent.getBooleanExtra("probe_now", false)) {
            String path = getFilesDir() + "/harness_ra_renamed.txt";
            android.util.Log.i("HarnessProbe", "post-block writeErr="
                    + nativeProbeWrite(path) + " text=" + nativeProbeText(path));
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.i(TAG, "onResume");
        if (servicesStarted) {
            return;
        }
        servicesStarted = true;
        try {
            startService(new Intent(this, HarnessService.class));
            startService(new Intent(this, HarnessRemoteService.class));
            new Thread(() -> HarnessStorage.holdLockFor(
                    this, "harness_lock.txt", 2000), "harness-lock").start();
            startService(new Intent(this, HarnessRemoteService.class)
                    .putExtra("lock_probe", true));
        } catch (IllegalStateException error) {
            Log.w(TAG, "service start not allowed in current state", error);
        }
    }

    public native String stringFromJNI();

    public native int nativeProbeWrite(String path);

    public native int nativeProbeRead(String path);

    public native int nativeProbeMmap(String path);

    public native int nativeProbeSyscall(String path);

    public native String nativeProbeText(String path);

    public native int nativeProbeWriteText(String path, String value);

    public native int nativeProbeMmapWrite(String path, String value);

    public native int nativeProbeHoldWrite(String path, String value, int millis);

    public native int nativeProbeDupWrite(String path, String value);
}
