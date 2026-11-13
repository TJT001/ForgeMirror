package dev.forgemirror.shield;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Storage facade entry points. The S5/S6 call-site rewrite redirects business
 * getSharedPreferences/openFileOutput/openFileInput calls here; paths matched
 * by the policy are transparently encrypted, everything else passes through.
 */
public final class ShieldStorage {
    private ShieldStorage() {
    }

    public static SharedPreferences getSharedPreferences(
            Context context, String name, int mode) {
        Context base = context.getApplicationContext() != null
                ? context.getApplicationContext() : context;
        return ShieldContextAdapter.sharedPreferences(base, name, mode);
    }

    public static FileOutputStream openFileOutput(Context context, String name, int mode)
            throws java.io.FileNotFoundException {
        Context base = context.getApplicationContext() != null
                ? context.getApplicationContext() : context;
        return ShieldContextAdapter.openFileOutput(base, name, mode);
    }

    public static FileInputStream openFileInput(Context context, String name)
            throws java.io.FileNotFoundException {
        Context base = context.getApplicationContext() != null
                ? context.getApplicationContext() : context;
        return ShieldContextAdapter.openFileInput(base, name);
    }

    public static ShieldRandomAccess openRandomAccessFile(
            Context context, String name, String mode) throws java.io.FileNotFoundException {
        Context base = context.getApplicationContext() != null
                ? context.getApplicationContext() : context;
        return ShieldContextAdapter.openRandomAccessFile(base, name, mode);
    }

    /** Debug-only response check; does nothing for non-debuggable apps. */
    public static void showDemoToast(Context context) {
        if ((context.getApplicationInfo().flags
                & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            return;
        }
        java.util.List<ShieldDetect.Finding> findings = new java.util.ArrayList<>();
        findings.add(new ShieldDetect.Finding("env_demo", "demo", "manual", 0.1));
        ShieldResponse.dispatch(context, findings, "toast");
    }
}
