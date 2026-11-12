package dev.forgemirror.demo;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import dev.forgemirror.shield.ShieldRuntime;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";

    private boolean servicesStarted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        setContentView(tv);
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

        tv.setText(ShieldRuntime.describe() + "\n" + providerStatus);
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
        } catch (IllegalStateException error) {
            Log.w(TAG, "service start not allowed in current state", error);
        }
    }
}
