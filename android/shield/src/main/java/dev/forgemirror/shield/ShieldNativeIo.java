package dev.forgemirror.shield;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.FileDescriptor;
import android.util.Log;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * Plaintext memfd snapshots for libc-level access. Writes are flushed back to
 * the encrypted FMF2 file on fsync/close; this keeps direct native I/O working
 * without exposing plaintext on disk.
 */
final class ShieldNativeIo {
    private static final String TAG = "ShieldNativeIo";
    private static long maxFileBytes = 128L << 20;
    private static final Map<Integer, State> OPEN = new HashMap<>();

    private static Context appContext;

    private ShieldNativeIo() {
    }

    static void configure(Context context, int maxFileMb) {
        appContext = context.getApplicationContext() != null
                ? context.getApplicationContext() : context;
        if (maxFileMb >= 1 && maxFileMb <= 1024) {
            maxFileBytes = (long) maxFileMb << 20;
        }
    }

    static synchronized int open(String path, boolean writable) {
        if (appContext == null || path == null) {
            return -1;
        }
        byte[] key = ShieldRuntime.fileKey();
        if (key == null) {
            return -1;
        }
        String relative = relativePath(appContext, path);
        if (relative == null || !ShieldRuntime.protects(relative)) {
            return -1;
        }
        File target = new File(path);
        if (!writable && !target.isFile()) {
            return -1;
        }
        try {
            byte[] plaintext = target.isFile()
                    ? ShieldFiles.readAllPlaintext(target, key)
                    : new byte[0];
            if (plaintext.length > maxFileBytes) {
                return -1;
            }
            android.os.ParcelFileDescriptor descriptor = writeMemfd(plaintext);
            int fd = descriptor.getFd();
            synchronized (ShieldNativeIo.class) {
                OPEN.put(fd, new State(target, writable, key, descriptor));
            }
            Log.i(TAG, "open shadow fd=" + fd + " path=" + path
                    + " writable=" + writable + " bytes=" + plaintext.length);
            return fd;
        } catch (Exception error) {
            Log.w(TAG, "shadow open failed: " + error);
            return -1;
        }
    }

    static synchronized void sync(int fd, boolean close) {
        State state = OPEN.get(fd);
        if (state == null) {
            return;
        }
        if (state.writable) {
            try {
                StructStat stat = Os.fstat(state.descriptor.getFileDescriptor());
                long size = stat.st_size;
                if (size > maxFileBytes) {
                    throw new IllegalStateException("file too large");
                }
                byte[] data = new byte[(int) size];
                if (size > 0) {
                    int read = Os.pread(state.descriptor.getFileDescriptor(),
                            data, 0, data.length, 0);
                    if (read != data.length) {
                        throw new IllegalStateException("short pread: " + read);
                    }
                }
                ShieldChunkStore.writeAll(state.target, state.key, data);
                Log.i(TAG, "sync fd=" + fd + " bytes=" + data.length);
            } catch (Exception error) {
                Log.w(TAG, "shadow sync failed: " + error);
            }
        }
        if (close) {
            OPEN.remove(fd);
            try {
                state.descriptor.detachFd();
            } catch (Exception error) {
                Log.w(TAG, "detach failed: " + error);
            }
        }
    }

    static synchronized boolean tracked(int fd) {
        return OPEN.containsKey(fd);
    }

    private static ParcelFileDescriptor writeMemfd(byte[] data) throws Exception {
        FileDescriptor source = Os.memfd_create("forgemirror-io", 0);
        int offset = 0;
        while (offset < data.length) {
            int written = Os.write(source, data, offset, data.length - offset);
            if (written <= 0) {
                throw new IllegalStateException("memfd write stalled");
            }
            offset += written;
        }
        Os.lseek(source, 0, OsConstants.SEEK_SET);
        ParcelFileDescriptor descriptor = ParcelFileDescriptor.dup(source);
        Os.close(source);
        return descriptor;
    }

    private static String relativePath(Context context, String path) {
        String dataDir = context.getApplicationInfo().dataDir;
        if (path.startsWith(dataDir + "/files/")) {
            return "files/" + path.substring((dataDir + "/files/").length());
        }
        if (path.startsWith(dataDir + "/shared_prefs/")) {
            return "shared_prefs/" + path.substring((dataDir + "/shared_prefs/").length());
        }
        return null;
    }

    private static final class State {
        final File target;
        final boolean writable;
        final byte[] key;
        final ParcelFileDescriptor descriptor;

        State(File target, boolean writable, byte[] key, ParcelFileDescriptor descriptor) {
            this.target = target;
            this.writable = writable;
            this.key = key;
            this.descriptor = descriptor;
        }
    }
}
