package dev.forgemirror.shield;

import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Encrypted replacements for Context.openFileOutput/openFileInput on paths the
 * policy matches. Output buffers in memory and persists FMF2 at close (append
 * uses the same cross-process merge as native I/O); input serves decrypted
 * bytes through a pipe so callers still receive a genuine FileInputStream.
 */
final class ShieldFiles {
    private static final String TAG = "ShieldFiles";
    private static final int MAX_BUFFER = 64 << 20;

    private ShieldFiles() {
    }

    static FileOutputStream openOutput(File target, int mode, byte[] key)
            throws FileNotFoundException {
        boolean append = (mode & android.content.Context.MODE_APPEND) != 0;
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new FileNotFoundException("cannot create " + parent);
        }
        try {
            return new ShieldFileOutputStream(target, key, append);
        } catch (IOException error) {
            FileNotFoundException failure = new FileNotFoundException(target.getPath());
            failure.initCause(error);
            throw failure;
        }
    }

    static ShieldRandomAccess openRandomAccess(File target, byte[] key, String mode)
            throws FileNotFoundException {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new FileNotFoundException("cannot create " + parent);
        }
        try {
            return new ShieldRandomAccess(target, key, mode);
        } catch (IOException error) {
            FileNotFoundException failure = new FileNotFoundException(target.getPath());
            failure.initCause(error);
            throw failure;
        }
    }

    static byte[] readAllPlaintext(File source, byte[] key) throws IOException {
        if (!source.isFile()) {
            return new byte[0];
        }
        if (ShieldChunkStore.matches(source)) {
            return ShieldChunkStore.readAll(source, key);
        }
        byte[] blob = new byte[(int) source.length()];
        try (FileInputStream in = new FileInputStream(source)) {
            int offset = 0;
            while (offset < blob.length) {
                int read = in.read(blob, offset, blob.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        }
        if (!ShieldCrypto.isFileEncrypted(blob)) {
            return blob;
        }
        try {
            return ShieldCrypto.fileDecrypt(blob, key);
        } catch (Exception error) {
            throw new IOException("encrypted file rejected: " + source, error);
        }
    }

    static FileInputStream openInput(File source, byte[] key) throws IOException {
        if (!source.isFile()) {
            throw new FileNotFoundException(source.getPath());
        }
        if (ShieldChunkStore.matches(source)) {
            return pipeInput(ShieldChunkStore.readAll(source, key));
        }
        byte[] blob = new byte[(int) source.length()];
        try (FileInputStream in = new FileInputStream(source)) {
            int offset = 0;
            while (offset < blob.length) {
                int read = in.read(blob, offset, blob.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        }
        byte[] plaintext;
        if (ShieldCrypto.isFileEncrypted(blob)) {
            try {
                plaintext = ShieldCrypto.fileDecrypt(blob, key);
            } catch (Exception error) {
                throw new IOException("encrypted file rejected: " + source, error);
            }
        } else {
            // Legacy plaintext file: read as-is; the next write re-encrypts.
            plaintext = blob;
        }
        return pipeInput(plaintext);
    }

    private static FileInputStream pipeInput(byte[] data) throws IOException {
        final java.io.FileDescriptor[] pipe;
        try {
            pipe = Os.pipe();
        } catch (ErrnoException error) {
            throw new IOException("pipe failed", error);
        }
        Thread writer = new Thread(() -> {
            try {
                int offset = 0;
                while (offset < data.length) {
                    int chunk = Math.min(65536, data.length - offset);
                    offset += Os.write(pipe[1], data, offset, chunk);
                }
            } catch (Throwable error) {
                // Reader closed early (EPIPE) is normal; anything else is logged.
                Log.w(TAG, "pipe writer ended: " + error);
            } finally {
                try {
                    Os.close(pipe[1]);
                } catch (ErrnoException ignored) {
                    // Already closed.
                }
            }
        }, "shield-file-pipe");
        writer.setDaemon(true);
        writer.start();
        return new FileInputStream(pipe[0]);
    }

    private static final class ShieldFileOutputStream extends FileOutputStream {
        private final File target;
        private final byte[] key;
        private final boolean append;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final byte[] baselineFileId;
        private final int baselineChunkSize;
        private final int baselineLength;
        private final byte[][] baselineHashes;
        private boolean closed;

        ShieldFileOutputStream(File target, byte[] key, boolean append) throws IOException {
            super(new File(target.getParentFile(), target.getName() + ".tmp"));
            this.target = target;
            this.key = key;
            this.append = append;
            byte[] existing = new byte[0];
            byte[] fileId = null;
            int chunkSize = ShieldChunkStore.DEFAULT_CHUNK_SIZE;
            byte[][] hashes = null;
            if (append && target.isFile()) {
                if (ShieldChunkStore.matches(target)) {
                    try (ShieldChunkStore store =
                                 ShieldChunkStore.open(target, key, "r")) {
                        existing = store.readAllBytes();
                        chunkSize = store.chunkSize();
                        fileId = store.fileIdCopy();
                        hashes = ShieldChunkStore.chunkHashes(existing, chunkSize);
                    }
                } else {
                    existing = ShieldFiles.readAllPlaintext(target, key);
                }
                buffer.write(existing, 0, existing.length);
            }
            this.baselineFileId = fileId;
            this.baselineChunkSize = chunkSize;
            this.baselineLength = existing.length;
            this.baselineHashes = hashes;
        }

        @Override
        public void write(int oneByte) throws IOException {
            buffer.write(oneByte);
        }

        @Override
        public void write(byte[] data) throws IOException {
            buffer.write(data, 0, data.length);
        }

        @Override
        public void write(byte[] data, int offset, int count) throws IOException {
            buffer.write(data, offset, count);
        }

        @Override
        public synchronized void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            if (buffer.size() > MAX_BUFFER) {
                throw new IOException("encrypted file too large for in-memory buffer");
            }
            byte[] plaintext = buffer.toByteArray();
            try {
                if (append && baselineHashes != null) {
                    ShieldChunkStore.MergeResult result =
                            ShieldChunkStore.writeMerged(target, key, plaintext,
                                    baselineFileId, baselineChunkSize,
                                    baselineLength, baselineHashes);
                    if (result.conflicts > 0) {
                        Log.w(TAG, "merge conflicts=" + result.conflicts
                                + " path=" + target);
                    }
                } else {
                    ShieldChunkStore.writeAll(target, key, plaintext);
                }
            } finally {
                super.close();
                File temp = new File(target.getParentFile(),
                        target.getName() + ".tmp");
                if (temp.isFile()) {
                    //noinspection ResultOfMethodCallIgnored
                    temp.delete();
                }
            }
        }
    }
}
