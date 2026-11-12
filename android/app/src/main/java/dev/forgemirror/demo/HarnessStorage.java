package dev.forgemirror.demo;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class HarnessStorage {
    private static final String TAG = "HarnessStorage";

    private HarnessStorage() {
    }

    public static void exercise(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("harness_prefs", Context.MODE_PRIVATE);
        prefs.edit().putString("last_write", Long.toString(System.currentTimeMillis())).apply();

        File file = new File(context.getFilesDir(), "harness.txt");
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(("harness " + System.currentTimeMillis() + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        } catch (IOException error) {
            Log.e(TAG, "file write failed", error);
        }

        SQLiteDatabase database = context.openOrCreateDatabase("harness.db", Context.MODE_PRIVATE, null);
        try {
            database.execSQL(
                    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL)");
            database.execSQL("INSERT INTO events(value) VALUES (?)", new Object[]{"row"});
        } finally {
            database.close();
        }
    }
}
