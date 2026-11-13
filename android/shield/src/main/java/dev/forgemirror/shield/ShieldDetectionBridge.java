package dev.forgemirror.shield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.util.Log;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** Carries findings from secondary processes to the main process. */
final class ShieldDetectionBridge {
    private static final String TAG = "ShieldDetectionBridge";
    private static final String ACTION = "dev.forgemirror.shield.DETECTION";

    private ShieldDetectionBridge() {
    }

    static void register(Context context) {
        if (!ShieldProcess.isMain(context)) {
            return;
        }
        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context receiverContext, Intent intent) {
                handle(receiverContext, intent);
            }
        };
        IntentFilter filter = new IntentFilter(ACTION);
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            context.registerReceiver(receiver, filter);
        }
        Log.i(TAG, "registered");
    }

    static void send(Context context, List<ShieldDetect.Finding> findings) {
        if (findings.isEmpty()) {
            return;
        }
        Intent intent = new Intent(ACTION).setPackage(context.getPackageName());
        String[] rules = new String[findings.size()];
        String[] kinds = new String[findings.size()];
        String[] evidence = new String[findings.size()];
        double[] confidence = new double[findings.size()];
        for (int index = 0; index < findings.size(); index++) {
            ShieldDetect.Finding finding = findings.get(index);
            rules[index] = finding.ruleId;
            kinds[index] = finding.kind;
            evidence[index] = finding.evidence;
            confidence[index] = finding.confidence;
        }
        intent.putExtra("rules", rules);
        intent.putExtra("kinds", kinds);
        intent.putExtra("evidence", evidence);
        intent.putExtra("confidence", confidence);
        context.sendBroadcast(intent);
    }

    private static void handle(Context context, Intent intent) {
        String[] rules = intent.getStringArrayExtra("rules");
        String[] kinds = intent.getStringArrayExtra("kinds");
        String[] evidence = intent.getStringArrayExtra("evidence");
        double[] confidence = intent.getDoubleArrayExtra("confidence");
        if (rules == null || kinds == null || evidence == null) {
            return;
        }
        List<ShieldDetect.Finding> findings = new ArrayList<>();
        for (int index = 0; index < rules.length; index++) {
            String rule = rules[index];
            String kind = index < kinds.length ? kinds[index] : "unknown";
            String item = index < evidence.length ? evidence[index] : rule;
            double score = confidence != null && index < confidence.length
                    ? confidence[index] : 0.5;
            findings.add(new ShieldDetect.Finding(rule, kind, item, score));
            try {
                JSONObject payload = new JSONObject();
                payload.put("kind", kind);
                payload.put("evidence", item);
                payload.put("source", "secondary_process");
                ShieldEvents.record("runtime_detection", rule, score,
                        ShieldDetect.hash(item), payload);
            } catch (Exception error) {
                Log.w(TAG, "bridge record failed: " + error);
            }
        }
        ShieldResponse.dispatch(context, findings,
                ShieldServerConfig.response(context, "toast"));
    }
}
