package dev.forgemirror.shield;

import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SharedPreferences implementation backed by an FMF1-encrypted file at the
 * standard shared_prefs path. Supports String/int/long/float/boolean and
 * StringSet values, synchronous commit, asynchronous apply, and change
 * listeners. Corrupt or tampered files start empty (GCM failure rejects them).
 */
final class ShieldSharedPreferences implements SharedPreferences {
    private static final String TAG = "ShieldPrefs";
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor();

    private final Object lock = new Object();
    private final File file;
    private final byte[] key;
    private final HashMap<String, Object> values = new HashMap<>();
    private final CopyOnWriteArrayList<OnSharedPreferenceChangeListener> listeners =
            new CopyOnWriteArrayList<>();

    ShieldSharedPreferences(File file, byte[] key) {
        this.file = file;
        this.key = key;
        load();
    }

    private void load() {
        if (!file.isFile()) {
            return;
        }
        try {
            byte[] blob = readFile(file);
            if (!ShieldCrypto.isFileEncrypted(blob)) {
                Log.w(TAG, "plaintext legacy prefs, starting empty: " + file.getName());
                return;
            }
            JSONObject json = new JSONObject(
                    new String(ShieldCrypto.fileDecrypt(blob, key), StandardCharsets.UTF_8));
            for (Iterator<String> it = json.keys(); it.hasNext(); ) {
                String name = it.next();
                values.put(name, fromJson(json.get(name)));
            }
        } catch (Throwable error) {
            Log.w(TAG, "prefs load rejected for " + file.getName() + ": " + error);
            values.clear();
        }
    }

    private static Object fromJson(Object value) throws org.json.JSONException {
        if (value instanceof JSONArray) {
            HashSet<String> set = new HashSet<>();
            JSONArray array = (JSONArray) value;
            for (int index = 0; index < array.length(); index++) {
                set.add(array.getString(index));
            }
            return set;
        }
        return value;
    }

    private static Object toJson(Object value) {
        if (value instanceof Set) {
            JSONArray array = new JSONArray();
            for (String item : (Set<String>) value) {
                array.put(item);
            }
            return array;
        }
        return value;
    }

    private void persistLocked() throws Exception {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            json.put(entry.getKey(), toJson(entry.getValue()));
        }
        byte[] blob = ShieldCrypto.fileEncrypt(
                json.toString().getBytes(StandardCharsets.UTF_8), key);
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create " + parent);
        }
        File temp = new File(parent, file.getName() + ".tmp");
        FileOutputStream out = new FileOutputStream(temp);
        try {
            out.write(blob);
            out.getFD().sync();
        } finally {
            out.close();
        }
        if (!temp.renameTo(file)) {
            throw new IllegalStateException("atomic rename failed: " + file);
        }
    }

    private static byte[] readFile(File file) throws Exception {
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = in.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
            return buffer.toByteArray();
        }
    }

    @Override
    public Map<String, ?> getAll() {
        synchronized (lock) {
            return new HashMap<>(values);
        }
    }

    @Override
    public String getString(String name, String defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            return value instanceof String ? (String) value : defValue;
        }
    }

    @Override
    public Set<String> getStringSet(String name, Set<String> defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            return value instanceof Set ? new HashSet<>((Set<String>) value) : defValue;
        }
    }

    @Override
    public int getInt(String name, int defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            return value instanceof Integer ? (Integer) value : defValue;
        }
    }

    @Override
    public long getLong(String name, long defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            if (value instanceof Long) {
                return (Long) value;
            }
            if (value instanceof Integer) {
                return (Integer) value;
            }
            return defValue;
        }
    }

    @Override
    public float getFloat(String name, float defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            return value instanceof Float ? (Float) value : defValue;
        }
    }

    @Override
    public boolean getBoolean(String name, boolean defValue) {
        synchronized (lock) {
            Object value = values.get(name);
            return value instanceof Boolean ? (Boolean) value : defValue;
        }
    }

    @Override
    public boolean contains(String name) {
        synchronized (lock) {
            return values.containsKey(name);
        }
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        listeners.add(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(
            OnSharedPreferenceChangeListener listener) {
        listeners.remove(listener);
    }

    private final class Editor implements SharedPreferences.Editor {
        private final HashMap<String, Object> puts = new HashMap<>();
        private final HashSet<String> removes = new HashSet<>();
        private boolean clearAll;

        private Editor() {
        }

        @Override
        public Editor putString(String name, String value) {
            synchronized (puts) {
                if (value == null) {
                    removes.add(name);
                    puts.remove(name);
                } else {
                    puts.put(name, value);
                }
            }
            return this;
        }

        @Override
        public Editor putStringSet(String name, Set<String> values) {
            synchronized (puts) {
                if (values == null) {
                    removes.add(name);
                    puts.remove(name);
                } else {
                    puts.put(name, new HashSet<>(values));
                }
            }
            return this;
        }

        @Override
        public Editor putInt(String name, int value) {
            synchronized (puts) {
                puts.put(name, value);
            }
            return this;
        }

        @Override
        public Editor putLong(String name, long value) {
            synchronized (puts) {
                puts.put(name, value);
            }
            return this;
        }

        @Override
        public Editor putFloat(String name, float value) {
            synchronized (puts) {
                puts.put(name, value);
            }
            return this;
        }

        @Override
        public Editor putBoolean(String name, boolean value) {
            synchronized (puts) {
                puts.put(name, value);
            }
            return this;
        }

        @Override
        public Editor remove(String name) {
            synchronized (puts) {
                removes.add(name);
                puts.remove(name);
            }
            return this;
        }

        @Override
        public Editor clear() {
            synchronized (puts) {
                clearAll = true;
                puts.clear();
                removes.clear();
            }
            return this;
        }

        @Override
        public boolean commit() {
            return commitInternal();
        }

        @Override
        public void apply() {
            EXECUTOR.execute(this::commitInternal);
        }

        private boolean commitInternal() {
            HashSet<String> changed = new HashSet<>();
            boolean ok;
            synchronized (lock) {
                if (clearAll) {
                    changed.addAll(values.keySet());
                    values.clear();
                }
                for (String name : removes) {
                    if (values.remove(name) != null) {
                        changed.add(name);
                    }
                }
                for (Map.Entry<String, Object> entry : puts.entrySet()) {
                    values.put(entry.getKey(), entry.getValue());
                    changed.add(entry.getKey());
                }
                try {
                    persistLocked();
                    ok = true;
                } catch (Throwable error) {
                    Log.e(TAG, "prefs commit failed: " + error);
                    ok = false;
                }
            }
            for (String name : changed) {
                for (OnSharedPreferenceChangeListener listener : listeners) {
                    listener.onSharedPreferenceChanged(ShieldSharedPreferences.this, name);
                }
            }
            return ok;
        }
    }
}
