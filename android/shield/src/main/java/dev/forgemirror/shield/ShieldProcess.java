package dev.forgemirror.shield;

import android.app.Application;
import android.content.Context;

/** Process-name helper; background work that must not be duplicated lives in the main process. */
final class ShieldProcess {
    private ShieldProcess() {
    }

    static boolean isMain(Context context) {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 28) {
                String name = Application.getProcessName();
                return name == null || name.equals(context.getPackageName());
            }
            byte[] raw = new byte[256];
            try (java.io.FileInputStream in = new java.io.FileInputStream("/proc/self/cmdline")) {
                int length = in.read(raw);
                if (length <= 0) {
                    return true;
                }
                int end = 0;
                while (end < length && raw[end] != 0) {
                    end++;
                }
                String name = new String(raw, 0, end, java.nio.charset.StandardCharsets.UTF_8);
                return name.equals(context.getPackageName());
            }
        } catch (Throwable error) {
            return true;
        }
    }
}
