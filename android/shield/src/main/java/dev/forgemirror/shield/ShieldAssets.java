package dev.forgemirror.shield;

import android.content.Context;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class ShieldAssets {
    private ShieldAssets() {
    }

    static byte[] read(Context context, String path) throws IOException {
        try (InputStream stream = context.getAssets().open(path)) {
            return readAll(stream);
        }
    }

    static byte[] readAll(InputStream stream) throws IOException {
        byte[] buffer = new byte[8192];
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        int read;
        while ((read = stream.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    static String readText(Context context, String path) throws IOException {
        return new String(read(context, path), StandardCharsets.UTF_8);
    }

    static JSONObject readJson(Context context, String path) throws Exception {
        return new JSONObject(readText(context, path));
    }
}
