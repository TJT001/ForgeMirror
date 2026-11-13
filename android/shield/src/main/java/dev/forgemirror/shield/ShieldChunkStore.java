package dev.forgemirror.shield;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Chunked AEAD file format FMF2. Each fixed-size chunk slot carries its own
 * nonce and tag, so random writes re-key only the touched chunks. Persistence
 * writes a fresh header and all chunks to a temporary file, fsyncs, then
 * atomically replaces the target.
 */
final class ShieldChunkStore implements AutoCloseable {
    static final byte[] MAGIC = {'F', 'M', 'F', '2'};
    static final int VERSION = 2;
    static final int HEADER_SIZE = 72;
    static final int DEFAULT_CHUNK_SIZE = 65536;
    static final int NONCE_SIZE = 12;
    static final int TAG_SIZE = 16;
    static final long MAX_LENGTH = 1L << 30;

    private static final int AAD_SIZE = 4 + 2 + 16 + 4 + 4;
    private static final int RECORD_OVERHEAD = NONCE_SIZE + TAG_SIZE;
    private static final int MAX_CHUNK_SIZE = 1 << 20;
    private static final int MIN_CHUNK_SIZE = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final File target;
    private final byte[] key;
    private final boolean writable;
    private final Map<Integer, byte[]> dirty = new HashMap<>();

    private RandomAccessFile source;
    private RandomAccessFile lockFile;
    private FileChannel lockChannel;
    private FileLock lock;
    private byte[] fileId;
    private int chunkSize;
    private long length;
    private long persistedLength;
    private long zeroFrom = Long.MAX_VALUE;
    private int chunkCount;
    private int persistedCount;
    private boolean changed;
    private boolean closed;

    static ShieldChunkStore open(File target, byte[] key, String mode) throws IOException {
        return new ShieldChunkStore(target, key, mode, false);
    }

    static byte[] readAll(File target, byte[] key) throws IOException {
        if (!target.isFile() || target.length() == 0) {
            return new byte[0];
        }
        try (ShieldChunkStore store = open(target, key, "r")) {
            long length = store.length();
            if (length > MAX_LENGTH) {
                throw new IOException("file too large");
            }
            byte[] data = new byte[(int) length];
            int offset = 0;
            while (offset < data.length) {
                int read = store.read(offset, data, offset, data.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
            return data;
        }
    }

    static void writeAll(File target, byte[] key, byte[] plaintext) throws IOException {
        if (plaintext.length > MAX_LENGTH) {
            throw new IOException("file too large for FMF2");
        }
        ShieldChunkStore store = new ShieldChunkStore(target, key, "rw", true);
        store.length = plaintext.length;
        store.chunkCount = chunksFor(plaintext.length, store.chunkSize);
        for (int index = 0; index < store.chunkCount; index++) {
            byte[] chunk = new byte[store.chunkSize];
            int offset = index * store.chunkSize;
            System.arraycopy(plaintext, offset, chunk, 0,
                    Math.min(store.chunkSize, plaintext.length - offset));
            store.dirty.put(index, chunk);
        }
        store.changed = true;
        store.close();
    }

    static boolean matches(File file) {
        if (!file.isFile() || file.length() < MAGIC.length) {
            return false;
        }
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            byte[] magic = new byte[MAGIC.length];
            input.readFully(magic);
            return Arrays.equals(magic, MAGIC);
        } catch (IOException error) {
            return false;
        }
    }

    private ShieldChunkStore(File target, byte[] key, String mode, boolean blank)
            throws IOException {
        this.target = target;
        this.key = key;
        this.writable = !"r".equals(mode);
        if (!"r".equals(mode) && !"rw".equals(mode)
                && !"rws".equals(mode) && !"rwd".equals(mode)) {
            throw new IllegalArgumentException("unsupported mode: " + mode);
        }
        if (!writable && !target.isFile()) {
            throw new FileNotFoundException(target.getPath());
        }
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create " + parent);
        }
        acquireLock();
        try {
            deleteStaleTemp(target);
            if (!blank && target.isFile() && target.length() > 0) {
                source = new RandomAccessFile(target, writable ? "rw" : "r");
                readHeader();
            } else {
                if (!writable) {
                    throw new FileNotFoundException(target.getPath());
                }
                fileId = new byte[16];
                RANDOM.nextBytes(fileId);
                chunkSize = DEFAULT_CHUNK_SIZE;
                length = 0;
                persistedLength = 0;
                chunkCount = 0;
                persistedCount = 0;
                changed = true;
            }
        } catch (IOException | RuntimeException error) {
            releaseLock();
            throw error;
        }
    }

    private void acquireLock() throws IOException {
        File lockPath = lockPath(target);
        lockFile = new RandomAccessFile(lockPath, "rw");
        lockChannel = lockFile.getChannel();
        try {
            lock = writable
                    ? lockChannel.lock()
                    : lockChannel.lock(0, Long.MAX_VALUE, true);
        } catch (OverlappingFileLockException error) {
            releaseLock();
            throw new IOException("file is already open in this process: " + target,
                    error);
        }
    }

    private void releaseLock() {
        if (lock != null) {
            try {
                if (lock.isValid()) {
                    lock.release();
                }
            } catch (IOException ignored) {
                // Channel close below releases the OS lock.
            }
            lock = null;
        }
        if (lockChannel != null) {
            try {
                lockChannel.close();
            } catch (IOException ignored) {
                // Best effort.
            }
            lockChannel = null;
        }
        if (lockFile != null) {
            try {
                lockFile.close();
            } catch (IOException ignored) {
                // Best effort.
            }
            lockFile = null;
        }
    }

    long length() throws IOException {
        ensureOpen();
        return length;
    }

    int read(long offset, byte[] buffer, int bufferOffset, int count) throws IOException {
        ensureOpen();
        if (offset < 0) {
            throw new IOException("negative offset");
        }
        if (offset >= length) {
            return -1;
        }
        int read = (int) Math.min(count, length - offset);
        int done = 0;
        while (done < read) {
            long position = offset + done;
            int index = (int) (position / chunkSize);
            int within = (int) (position % chunkSize);
            byte[] chunk = loadChunk(index);
            int take = Math.min(read - done, chunk.length - within);
            System.arraycopy(chunk, within, buffer, bufferOffset + done, take);
            done += take;
        }
        return read;
    }

    void write(long offset, byte[] buffer, int bufferOffset, int count) throws IOException {
        ensureWritable();
        if (offset < 0 || count < 0) {
            throw new IOException("invalid write range");
        }
        if (count == 0) {
            return;
        }
        long end = offset + count;
        if (end > MAX_LENGTH) {
            throw new IOException("file too large for FMF2");
        }
        int previousCount = chunkCount;
        if (end > length) {
            length = end;
            chunkCount = chunksFor(length, chunkSize);
        }
        int done = 0;
        while (done < count) {
            long position = offset + done;
            int index = (int) (position / chunkSize);
            int within = (int) (position % chunkSize);
            byte[] chunk = dirty.get(index);
            if (chunk == null) {
                chunk = index < previousCount
                        ? loadChunk(index) : new byte[chunkSize];
            }
            int take = Math.min(count - done, chunkSize - within);
            System.arraycopy(buffer, bufferOffset + done, chunk, within, take);
            dirty.put(index, chunk);
            done += take;
        }
        changed = true;
    }

    void setLength(long newLength) throws IOException {
        ensureWritable();
        if (newLength < 0 || newLength > MAX_LENGTH) {
            throw new IOException("invalid length");
        }
        if (newLength < length) {
            zeroFrom = Math.min(zeroFrom, newLength);
            int newCount = chunksFor(newLength, chunkSize);
            for (Iterator<Integer> iterator = dirty.keySet().iterator();
                 iterator.hasNext(); ) {
                if (iterator.next() >= newCount) {
                    iterator.remove();
                }
            }
            if (newCount > 0) {
                int last = newCount - 1;
                int keep = (int) (newLength - (long) last * chunkSize);
                byte[] chunk = dirty.get(last);
                if (chunk == null && last < persistedCount) {
                    chunk = loadChunk(last);
                }
                if (chunk != null) {
                    Arrays.fill(chunk, keep, chunkSize, (byte) 0);
                    dirty.put(last, chunk);
                }
            }
        }
        length = newLength;
        chunkCount = chunksFor(newLength, chunkSize);
        changed = true;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (writable && changed) {
                persist();
            }
        } finally {
            if (source != null) {
                source.close();
                source = null;
            }
            releaseLock();
        }
    }

    private void persist() throws IOException {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create " + parent);
        }
        File temp = temp(target);
        try (RandomAccessFile output = new RandomAccessFile(temp, "rw")) {
            output.setLength(0);
            byte[] header = buildHeader();
            output.write(header);
            for (int index = 0; index < chunkCount; index++) {
                int chunkLength = chunkLength(index);
                boolean copyable = !dirty.containsKey(index)
                        && index < persistedCount
                        && chunkLength == persistedChunkLength(index)
                        && (long) index * chunkSize < zeroFrom;
                if (copyable) {
                    copyRecord(output, index);
                    continue;
                }
                byte[] chunk = dirty.get(index);
                if (chunk == null) {
                    chunk = loadChunk(index);
                }
                byte[] padded = chunk.length == chunkSize
                        ? chunk : Arrays.copyOf(chunk, chunkSize);
                byte[] nonce = ShieldCrypto.randomNonce();
                byte[] ciphertext = ShieldCrypto.gcmEncrypt(
                        key, nonce, padded, chunkAad(index, chunkLength));
                output.write(nonce);
                output.write(ciphertext);
            }
            output.getFD().sync();
        } catch (Exception error) {
            //noinspection ResultOfMethodCallIgnored
            temp.delete();
            throw new IOException("FMF2 persist failed: " + target, error);
        }
        if (source != null) {
            source.close();
            source = null;
        }
        try {
            Files.move(temp.toPath(), target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException moveFailure) {
            if (!temp.renameTo(target)) {
                throw new IOException("atomic move failed: " + target, moveFailure);
            }
        }
        dirty.clear();
        persistedCount = chunkCount;
        persistedLength = length;
        zeroFrom = Long.MAX_VALUE;
        changed = false;
    }

    private void copyRecord(RandomAccessFile output, int index) throws IOException {
        byte[] buffer = new byte[8192];
        long offset = HEADER_SIZE + (long) index * (chunkSize + RECORD_OVERHEAD);
        source.seek(offset);
        int remaining = chunkSize + RECORD_OVERHEAD;
        while (remaining > 0) {
            int read = source.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read < 0) {
                throw new IOException("truncated FMF2 record");
            }
            output.write(buffer, 0, read);
            remaining -= read;
        }
    }

    private void readHeader() throws IOException {        if (source.length() < HEADER_SIZE) {
            throw new IOException("truncated FMF2 header");
        }
        byte[] header = new byte[HEADER_SIZE];
        source.seek(0);
        source.readFully(header);
        if (header[0] != MAGIC[0] || header[1] != MAGIC[1]
                || header[2] != MAGIC[2] || header[3] != MAGIC[3]) {
            throw new IOException("bad FMF2 magic");
        }
        ByteBuffer buffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int version = Short.toUnsignedInt(buffer.getShort(4));
        int algorithm = header[6] & 0xff;
        int size = buffer.getInt(24);
        long plaintextLength = buffer.getLong(28);
        int count = buffer.getInt(36);
        if (version != VERSION || algorithm != 1
                || size < MIN_CHUNK_SIZE || size > MAX_CHUNK_SIZE
                || (size & (size - 1)) != 0
                || plaintextLength < 0 || plaintextLength > MAX_LENGTH
                || count < 0) {
            throw new IOException("unsupported FMF2 header");
        }
        long expectedCount = (plaintextLength + size - 1) / size;
        if (expectedCount > Integer.MAX_VALUE || count != (int) expectedCount) {
            throw new IOException("FMF2 chunk count mismatch");
        }
        long expectedSize = HEADER_SIZE
                + (long) count * (size + RECORD_OVERHEAD);
        if (source.length() != expectedSize) {
            throw new IOException("FMF2 length mismatch");
        }
        byte[] fileId = Arrays.copyOfRange(header, 8, 24);
        byte[] nonce = Arrays.copyOfRange(header, 40, 52);
        byte[] tag = Arrays.copyOfRange(header, 52, 68);
        byte[] aad = Arrays.copyOf(header, 52);
        try {
            byte[] plaintext = ShieldCrypto.gcmDecrypt(key, nonce, tag, aad);
            if (plaintext.length != 0) {
                throw new IOException("bad FMF2 header tag");
            }
        } catch (IOException error) {
            throw error;
        } catch (Exception error) {
            throw new IOException("bad FMF2 header tag", error);
        }
        this.fileId = fileId;
        this.chunkSize = size;
        this.length = plaintextLength;
        this.persistedLength = plaintextLength;
        this.chunkCount = count;
        this.persistedCount = count;
        this.changed = false;
    }

    private byte[] buildHeader() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MAGIC);
        buffer.putShort((short) VERSION);
        buffer.put((byte) 1);
        buffer.put((byte) 0);
        buffer.put(fileId);
        buffer.putInt(chunkSize);
        buffer.putLong(length);
        buffer.putInt(chunkCount);
        byte[] nonce = ShieldCrypto.randomNonce();
        buffer.put(nonce);
        byte[] aad = Arrays.copyOf(buffer.array(), 52);
        byte[] tag = ShieldCrypto.gcmEncrypt(key, nonce, new byte[0], aad);
        buffer.put(tag);
        buffer.putInt(0);
        return buffer.array();
    }

    private byte[] loadChunk(int index) throws IOException {
        byte[] cached = dirty.get(index);
        if (cached != null) {
            return cached;
        }
        byte[] chunk = new byte[chunkSize];
        if (index >= persistedCount
                || (long) index * chunkSize >= zeroFrom) {
            return chunk;
        }
        byte[] record = new byte[chunkSize + RECORD_OVERHEAD];
        source.seek(HEADER_SIZE + (long) index * (chunkSize + RECORD_OVERHEAD));
        source.readFully(record);
        byte[] nonce = Arrays.copyOfRange(record, 0, NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(record, NONCE_SIZE, record.length);
        try {
            byte[] plaintext = ShieldCrypto.gcmDecrypt(
                    key, nonce, ciphertext,
                    chunkAad(index, persistedChunkLength(index)));
            if (plaintext.length != chunkSize) {
                throw new IOException("bad FMF2 chunk length");
            }
            return plaintext;
        } catch (IOException error) {
            throw error;
        } catch (Exception error) {
            throw new IOException("FMF2 chunk rejected: " + index, error);
        }
    }

    private int chunkLength(int index) {
        return (int) Math.min(chunkSize, length - (long) index * chunkSize);
    }

    private int persistedChunkLength(int index) {
        return (int) Math.min(chunkSize,
                persistedLength - (long) index * chunkSize);
    }

    private byte[] chunkAad(int index, int chunkLength) {
        ByteBuffer buffer = ByteBuffer.allocate(AAD_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MAGIC);
        buffer.putShort((short) VERSION);
        buffer.put(fileId);
        buffer.putInt(index);
        buffer.putInt(chunkLength);
        return buffer.array();
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("file is closed");
        }
    }

    private void ensureWritable() throws IOException {
        ensureOpen();
        if (!writable) {
            throw new IOException("file is read-only");
        }
    }

    private static int chunksFor(long length, int chunkSize) {
        return (int) ((length + chunkSize - 1) / chunkSize);
    }

    private static File temp(File target) {
        return new File(target.getParentFile(), target.getName() + ".fmf2.tmp");
    }

    private static File lockPath(File target) {
        return new File(target.getParentFile(), "." + target.getName() + ".lock");
    }

    private static void deleteStaleTemp(File target) {
        File temp = temp(target);
        if (temp.isFile() && !temp.delete()) {
            // Best effort; the next persist overwrites it.
        }
    }
}
