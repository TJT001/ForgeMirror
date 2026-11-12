package dev.forgemirror.demo;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Process;
import android.util.Log;

public final class HarnessProvider extends ContentProvider {
    public static final String AUTHORITY = "dev.forgemirror.demo.harness";
    public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY + "/status");
    private static final String TAG = "HarnessProvider";

    @Override
    public boolean onCreate() {
        Log.i(TAG, "onCreate pid=" + Process.myPid());
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"value"}, 1);
        cursor.addRow(new Object[]{"ok"});
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.item/vnd.forgemirror.status";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
