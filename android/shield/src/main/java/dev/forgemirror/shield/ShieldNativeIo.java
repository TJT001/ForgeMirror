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
            return -2;
        }
        byte[] key = ShieldRuntime.fileKey();
        if (key == null) {
            return -2;
        }
        String relative = relativePath(appContext, path);
        if (relative == null || !ShieldRuntime.protects(relative)) {
            return -2;
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
            ParcelFileDescriptor exported =
                    ParcelFileDescriptor.dup(descriptor.getFileDescriptor());
            int fd = exported.detachFd();
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

    static boolean protectedPath(String path) {
        if (appContext == null || path == null) {
            return false;
        }
        String relative = relativePath(appContext, path);
        return relative != null && ShieldRuntime.protects(relative);
    }

    static synchronized void rememberDup(int oldFd, int newFd) {
        State state = OPEN.get(oldFd);
        if (state == null) {
            return;
        }
        State previous = OPEN.get(newFd);
        if (previous != null && previous != state) {
            previous.refs--;
            if (previous.refs <= 0) {
                try {
                    previous.descriptor.close();
                } catch (Exception ignored) {
                    // The replacement fd was already detached.
                }
            }
        }
        OPEN.put(newFd, state);
        state.refs++;
    }

    static synchronized void forgetDup(int fd) {
        State state = OPEN.remove(fd);
        if (state == null) {
            return;
        }
        state.refs--;
        if (state.refs <= 0) {
            try {
                state.descriptor.close();
            } catch (Exception ignored) {
                // The replacement fd was already detached.
            }
        }
    }

    static synchronized void sync(int fd, boolean close) {
        State state = OPEN.get(fd);
        if (state == null) {
            return;
        }
        if (!close) {
            persist(fd, state);
            return;
        }
        OPEN.remove(fd);
        if (--state.refs > 0) {
            return;
        }
        persist(fd, state);
        try {
            // The caller closes the exported fd separately; this is the
            // private memfd descriptor used for sync.
            state.descriptor.close();
        } catch (Exception error) {
            Log.w(TAG, "descriptor close failed: " + error);
        }
    }

    private static void persist(int fd, State state) {
        if (!state.writable) {
            return;
        }
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
        int refs = 1;

        State(File target, boolean writable, byte[] key, ParcelFileDescriptor descriptor) {
            this.target = target;
            this.writable = writable;
            this.key = key;
            this.descriptor = descriptor;
        }
    }
}
