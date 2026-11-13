package dev.forgemirror.demo;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class HarnessStorage {
    private static final String TAG = "HarnessStorage";

    private HarnessStorage() {
    }

    public static void exercise(Context context) {
        // P1-D call-site adaptation: business code calls the shield facade,
        // which the build step rewrites from context.getSharedPreferences /
        // context.openFileOutput call sites (design doc 16.4).
        SharedPreferences prefs =
                ShieldStorageFacade.getSharedPreferences(context, "harness_prefs");
        int counter = prefs.getInt("counter", 0);
        prefs.edit()
                .putString("last_write", Long.toString(System.currentTimeMillis()))
                .putInt("counter", counter + 1)
                .commit();
        Log.i(TAG, "prefs counter=" + (counter + 1));

        try (FileOutputStream out =
                     ShieldStorageFacade.openFileOutput(context, "harness.txt")) {
            out.write(("harness " + System.currentTimeMillis() + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        } catch (IOException error) {
            Log.e(TAG, "covered file write failed", error);
        }

        try (FileOutputStream out = ShieldStorageFacade.openFileOutput(
                context, "harness.txt", Context.MODE_APPEND)) {
            out.write("appended\n".getBytes(StandardCharsets.UTF_8));
        } catch (IOException error) {
            Log.e(TAG, "covered file append failed", error);
        }

        // Direct stream, no context openFileOutput call site: demonstrates the
        // interception boundary — this file stays plaintext by design in P1-D.
        File plain = new File(context.getFilesDir(), "harness_plain.txt");
        try (FileOutputStream out = new FileOutputStream(plain)) {
            out.write(("plain " + System.currentTimeMillis() + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        } catch (IOException error) {
            Log.e(TAG, "plain file write failed", error);
        }

        SQLiteDatabase database =
                context.openOrCreateDatabase("harness.db", Context.MODE_PRIVATE, null);
        try {
            database.execSQL(
                    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL)");
            database.execSQL("INSERT INTO events(value) VALUES (?)", new Object[]{"row"});
        } finally {
            database.close();
        }
    }

    public static String verify(Context context) {
        SharedPreferences prefs =
                ShieldStorageFacade.getSharedPreferences(context, "harness_prefs");
        String lastWrite = prefs.getString("last_write", null);
        int counter = prefs.getInt("counter", 0);

        String fileText = null;
        try (FileInputStream in = ShieldStorageFacade.openFileInput(context, "harness.txt")) {
            StringBuilder text = new StringBuilder();
            byte[] chunk = new byte[512];
            int read;
            while ((read = in.read(chunk)) != -1) {
                text.append(new String(chunk, 0, read, StandardCharsets.UTF_8));
            }
            fileText = text.toString().trim();
        } catch (IOException error) {
            Log.e(TAG, "covered file read failed", error);
        }

        boolean prefsOk = lastWrite != null && counter > 0;
        boolean fileOk = fileText != null && fileText.startsWith("harness ");
        boolean appendOk = fileText != null && fileText.contains("appended");
        return "readback prefs=" + prefsOk + " counter=" + counter
                + " file=" + fileOk + " append=" + appendOk;
    }
}
