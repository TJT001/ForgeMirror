package dev.forgemirror.shield;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Response dispatch. The default is a toast; there is deliberately no kill,
 * exit, or block path in P0.
 */
final class ShieldResponse {
    private static final String TAG = "ShieldResponse";

    private ShieldResponse() {
    }

    static void dispatch(Context context, List<ShieldDetect.Finding> findings, String mode) {
        if (findings.isEmpty()) {
            return;
        }
        Set<String> kinds = new LinkedHashSet<>();
        StringBuilder detail = new StringBuilder();
        for (ShieldDetect.Finding finding : findings) {
            if (!kinds.add(finding.kind)) {
                continue;
            }
            if (detail.length() > 0) {
                detail.append(", ");
            }
            detail.append(finding.kind);
        }
        Log.w(TAG, "response mode=" + mode + " kinds=" + detail);
        if (!"toast".equals(mode)) {
            return;
        }
        String text = "ForgeMirror 检测到运行环境异常：" + detail;
        Context appContext = context.getApplicationContext();
        Context toastContext = appContext != null ? appContext : context;
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(toastContext, text, Toast.LENGTH_LONG).show());
    }
}
