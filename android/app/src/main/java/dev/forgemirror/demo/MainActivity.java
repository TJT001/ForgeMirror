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

        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI() + "\n" + appStatus + "\n" + providerStatus
                + "\n" + HarnessStorage.verify(this));
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
}
