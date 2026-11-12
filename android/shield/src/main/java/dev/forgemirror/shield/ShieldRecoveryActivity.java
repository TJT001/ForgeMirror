package dev.forgemirror.shield;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public final class ShieldRecoveryActivity extends Activity {
    private static final String TAG = "ShieldRecovery";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "recovery activity state=" + ShieldRuntime.getState()
                + " reason=" + ShieldRuntime.getFailure());
        TextView view = new TextView(this);
        view.setText("ForgeMirror recovery\n" + ShieldRuntime.getFailure());
        view.setPadding(48, 96, 48, 48);
        setContentView(view);
    }
}
