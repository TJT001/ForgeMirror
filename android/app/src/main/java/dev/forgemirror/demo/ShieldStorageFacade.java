package dev.forgemirror.demo;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Call-site adaptation facade. The harness calls this explicitly; the general
 * S5/S6 step rewrites business DEX call sites context.getSharedPreferences /
 * openFileOutput / openFileInput to route through the shield facade so
 * policy-matched paths are transparently encrypted.
 */
public final class ShieldStorageFacade {
    private ShieldStorageFacade() {
    }

    public static SharedPreferences getSharedPreferences(Context context, String name) {
        return dev.forgemirror.shield.ShieldStorage.getSharedPreferences(
                context, name, Context.MODE_PRIVATE);
    }

    public static FileOutputStream openFileOutput(Context context, String name)
            throws java.io.FileNotFoundException {
        return dev.forgemirror.shield.ShieldStorage.openFileOutput(
                context, name, Context.MODE_PRIVATE);
    }

    public static FileInputStream openFileInput(Context context, String name)
            throws java.io.FileNotFoundException {
        return dev.forgemirror.shield.ShieldStorage.openFileInput(context, name);
    }
}
