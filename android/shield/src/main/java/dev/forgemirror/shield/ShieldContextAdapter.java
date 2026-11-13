package dev.forgemirror.shield;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Field;

/**
 * Patches the base ContextImpl instances so their getClassLoader() resolves
 * business classes from the memory loader, without introducing a wrapper type
 * (framework paths cast the application base context to ContextImpl and a
 * ContextWrapper breaks them). Also routes matched file/prefs calls through
 * encryption by intercepting the application-level entry points.
 */
final class ShieldContextAdapter {
    private ShieldContextAdapter() {
    }

    static void adaptClassLoader(Context context, ClassLoader loader) {
        if (context == null || loader == null) {
            return;
        }
        try {
            Class<?> implClass = Class.forName("android.app.ContextImpl");
            Field baseField = ContextWrapper.class.getDeclaredField("mBase");
            baseField.setAccessible(true);
            Context current = context;
            int depth = 0;
            while (current != null && depth < 8) {
                if (implClass.isInstance(current)) {
                    Field field = implClass.getDeclaredField("mClassLoader");
                    field.setAccessible(true);
                    if (field.get(current) != loader) {
                        field.set(current, loader);
                    }
                    return;
                }
                if (!(current instanceof ContextWrapper)) {
                    break;
                }
                current = (Context) baseField.get(current);
                depth++;
            }
            android.util.Log.w("ShieldContext",
                    "no ContextImpl under: " + context.getClass().getName());
        } catch (Throwable error) {
            android.util.Log.w("ShieldContext", "classloader patch failed", error);
        }
    }

    static SharedPreferences sharedPreferences(Context base, String name, int mode) {
        if (ShieldRuntime.protects("shared_prefs/" + name + ".xml")) {
            return ShieldRuntime.sharedPreferences(name, base);
        }
        return base.getSharedPreferences(name, mode);
    }

    static FileOutputStream openFileOutput(Context base, String name, int mode)
            throws java.io.FileNotFoundException {
        if (ShieldRuntime.protects("files/" + name)) {
            return ShieldFiles.openOutput(new File(base.getFilesDir(), name), mode,
                    ShieldRuntime.fileKey());
        }
        return base.openFileOutput(name, mode);
    }

    static FileInputStream openFileInput(Context base, String name)
            throws java.io.FileNotFoundException {
        if (ShieldRuntime.protects("files/" + name)) {
            try {
                return ShieldFiles.openInput(new File(base.getFilesDir(), name),
                        ShieldRuntime.fileKey());
            } catch (java.io.IOException error) {
                java.io.FileNotFoundException failure =
                        new java.io.FileNotFoundException(name);
                failure.initCause(error);
                throw failure;
            }
        }
        return base.openFileInput(name);
    }

    static ShieldRandomAccess openRandomAccessFile(Context base, String name, String mode)
            throws java.io.FileNotFoundException {
        if (ShieldRuntime.protects("files/" + name)) {
            return ShieldFiles.openRandomAccess(new File(base.getFilesDir(), name),
                    ShieldRuntime.fileKey(), mode);
        }
        return ShieldRandomAccess.plain(new File(base.getFilesDir(), name), mode);
    }
}
