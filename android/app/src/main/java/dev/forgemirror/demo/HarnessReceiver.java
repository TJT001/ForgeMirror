package dev.forgemirror.demo;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Process;
import android.util.Log;

public final class HarnessReceiver extends BroadcastReceiver {
    public static final String ACTION = "dev.forgemirror.demo.HARNESS_PING";
    private static final String TAG = "HarnessReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "onReceive action=" + intent.getAction() + " pid=" + Process.myPid());
    }
}
