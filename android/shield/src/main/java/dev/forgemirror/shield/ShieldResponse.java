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
        Set<String> toastKinds = new LinkedHashSet<>();
        for (ShieldDetect.Finding finding : findings) {
            if ("context".equals(finding.kind)) {
                continue;
            }
            String selected = ShieldServerConfig.responseFor(
                    context, finding.ruleId, mode);
            Log.w(TAG, "response rule=" + finding.ruleId + " mode=" + selected);
            if ("block".equals(selected) || "degrade".equals(selected)) {
                try {
                    ShieldNativeFileHook.setBlockMode(
                            "block".equals(selected) ? 2 : 1);
                } catch (Throwable error) {
                    Log.w(TAG, "block unavailable: " + error);
                }
                toastKinds.add(finding.kind);
            } else if ("toast".equals(selected)) {
                toastKinds.add(finding.kind);
            }
        }
        if (toastKinds.isEmpty()) {
            return;
        }
        StringBuilder detail = new StringBuilder();
        for (String kind : toastKinds) {
            if (detail.length() > 0) {
                detail.append(", ");
            }
            detail.append(kind);
        }
        String text = "ForgeMirror 检测到运行环境异常：" + detail;
        Context appContext = context.getApplicationContext();
        Context toastContext = appContext != null ? appContext : context;
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(toastContext, text, Toast.LENGTH_LONG).show());
    }
}
