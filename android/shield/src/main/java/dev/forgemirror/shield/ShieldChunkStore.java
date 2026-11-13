package dev.forgemirror.shield;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Chunked AEAD file format FMF2. Each fixed-size chunk slot carries its own
 * nonce and tag, so random writes re-key only the touched chunks. Persistence
 * writes a fresh header and all chunks to a temporary file, fsyncs, then
 * atomically replaces the target.
 */
final class ShieldChunkStore implements AutoCloseable {
    static final byte[] MAGIC = {'F', 'M', 'F', '2'};
    static final byte[] JOURNAL_MAGIC = {'F', 'M', 'J', '1'};
    static final byte[] WAL_MAGIC = {'F', 'M', 'W', '1'};
    static final int VERSION = 2;
    static final int JOURNAL_VERSION = 1;
    static final int JOURNAL_SIZE = 112;
    static final int WAL_VERSION = 1;
    static final int WAL_HEADER_SIZE = 128;
    static final int WAL_FOOTER_SIZE = 52;
    static final int WAL_RECORD_OVERHEAD = 36;
    static final int WAL_FLAG_FULL = 1;
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
        if (target.isFile() && matches(target)) {
            try (ShieldChunkStore store =
                         new ShieldChunkStore(target, key, "rw", false)) {
                store.replaceAll(plaintext);
                return;
            } catch (IOException | RuntimeException error) {
                // Corrupt or incompatible target: fall back to a full image.
            }
        }
        ShieldChunkStore store = new ShieldChunkStore(target, key, "rw", true);
        store.length = plaintext.length;
        store.chunkCount = chunksFor(plaintext.length, store.chunkSize);
        store.fillDirty(plaintext);
        store.changed = true;
        store.close();
    }

    private void replaceAll(byte[] plaintext) throws IOException {
        boolean changedAny = false;
        if (plaintext.length != length) {
            setLength(plaintext.length);
            changedAny = true;
        }
        byte[] current = new byte[chunkSize];
        for (int index = 0; index < chunkCount; index++) {
            int offset = index * chunkSize;
            int length = Math.min(chunkSize, plaintext.length - offset);
            int read = read(offset, current, 0, length);
            if (read < 0) {
                Arrays.fill(current, 0, length, (byte) 0);
            }
            boolean same = true;
            for (int cursor = 0; cursor < length; cursor++) {
                if (current[cursor] != plaintext[offset + cursor]) {
                    same = false;
                    break;
                }
            }
            if (!same) {
                write(offset, plaintext, offset, length);
                changedAny = true;
            }
        }
        changed = changedAny;
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
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create " + parent);
        }
        acquireLock();
        try {
            recover(target);
            if (!writable && !target.isFile()) {
                throw new FileNotFoundException(target.getPath());
            }
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
        File wal = writeWal();
        if (source != null) {
            source.close();
            source = null;
        }
        try {
            applyWalFile(target, wal, key);
        } catch (IOException error) {
            // The WAL is durable; a later open replays it.
            throw new IOException("FMF2 WAL apply failed: " + target + ": " + error, error);
        }
        dirty.clear();
        persistedCount = chunkCount;
        persistedLength = length;
        zeroFrom = Long.MAX_VALUE;
        changed = false;
    }

    static File prepareWal(File target, byte[] key, byte[] plaintext, boolean full)
            throws IOException {
        if (plaintext.length > MAX_LENGTH) {
            throw new IOException("file too large for FMF2");
        }
        ShieldChunkStore store = new ShieldChunkStore(target, key, "rw", full);
        store.length = plaintext.length;
        store.chunkCount = chunksFor(plaintext.length, store.chunkSize);
        store.fillDirty(plaintext);
        store.changed = true;
        File wal = store.writeWal();
        store.changed = false;
        store.close();
        return wal;
    }

    static File prepareWalPatch(File target, byte[] key, long offset,
                                byte[] data) throws IOException {
        ShieldChunkStore store = new ShieldChunkStore(target, key, "rw", false);
        store.write(offset, data, 0, data.length);
        File wal = store.writeWal();
        store.changed = false;
        store.close();
        return wal;
    }

    private void fillDirty(byte[] plaintext) {
        dirty.clear();
        for (int index = 0; index < chunkCount; index++) {
            byte[] chunk = new byte[chunkSize];
            int offset = index * chunkSize;
            System.arraycopy(plaintext, offset, chunk, 0,
                    Math.min(chunkSize, plaintext.length - offset));
            dirty.put(index, chunk);
        }
    }

    private boolean copyable(int index) {
        return !dirty.containsKey(index)
                && index < persistedCount
                && chunkLength(index) == persistedChunkLength(index)
                && (long) index * chunkSize < zeroFrom;
    }

    private File writeWal() throws IOException {
        boolean full = persistedCount == 0;
        List<Integer> changes = new ArrayList<>();
        for (int index = 0; index < chunkCount; index++) {
            if (!copyable(index)) {
                changes.add(index);
            }
        }
        if (full && changes.size() != chunkCount) {
            throw new IOException("full WAL must contain every chunk");
        }
        byte[] header;
        try {
            header = buildHeader();
        } catch (Exception error) {
            throw new IOException("cannot build FMF2 header", error);
        }
        byte[] baseFileId = full ? new byte[16] : Arrays.copyOf(fileId, 16);
        byte[] txn = new byte[16];
        RANDOM.nextBytes(txn);
        int recordBytes = changes.size() * (chunkSize + WAL_RECORD_OVERHEAD);
        ByteBuffer walHeader = ByteBuffer.allocate(WAL_HEADER_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN);
        walHeader.put(WAL_MAGIC);
        walHeader.putShort((short) WAL_VERSION);
        walHeader.putShort((short) (full ? WAL_FLAG_FULL : 0));
        walHeader.put(txn);
        walHeader.put(baseFileId);
        walHeader.put(header);
        walHeader.putInt(changes.size());
        walHeader.putInt(recordBytes);
        walHeader.putLong(0);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception error) {
            throw new IOException("SHA-256 unavailable", error);
        }
        File walTemp = walTemp(target);
        try (RandomAccessFile output = new RandomAccessFile(walTemp, "rw")) {
            output.setLength(0);
            byte[] headerBytes = walHeader.array();
            output.write(headerBytes);
            digest.update(headerBytes);
            for (int index : changes) {
                int length = chunkLength(index);
                byte[] chunk = dirty.get(index);
                if (chunk == null) {
                    chunk = loadChunk(index);
                }
                byte[] padded = chunk.length == chunkSize
                        ? chunk : Arrays.copyOf(chunk, chunkSize);
                byte[] nonce = ShieldCrypto.randomNonce();
                byte[] ciphertext = ShieldCrypto.gcmEncrypt(
                        key, nonce, padded, chunkAad(index, length));
                ByteBuffer record = ByteBuffer.allocate(20)
                        .order(ByteOrder.LITTLE_ENDIAN);
                record.putInt(index);
                record.putInt(length);
                record.put(nonce);
                output.write(record.array());
                digest.update(record.array());
                output.write(ciphertext);
                digest.update(ciphertext);
            }
            byte[] footer = new byte[WAL_FOOTER_SIZE];
            ByteBuffer footerBuffer = ByteBuffer.wrap(footer)
                    .order(ByteOrder.LITTLE_ENDIAN);
            footerBuffer.put(WAL_MAGIC);
            footerBuffer.put(txn);
            footerBuffer.put(digest.digest());
            output.write(footer);
            output.getFD().sync();
        } catch (Exception error) {
            deleteQuietly(walTemp);
            throw new IOException("FMF2 WAL write failed: " + target, error);
        }
        moveAtomic(walTemp, wal(target));
        fsyncDirectory(target.getParentFile());
        return wal(target);
    }

    private static WalInfo readWalInfo(File wal, byte[] key)
            throws IOException {
        long size = wal.length();
        if (size < WAL_HEADER_SIZE + WAL_FOOTER_SIZE) {
            throw new WalInvalidException("WAL too short");
        }
        byte[] header = new byte[WAL_HEADER_SIZE];
        try (RandomAccessFile input = new RandomAccessFile(wal, "r")) {
            input.readFully(header);
        }
        ByteBuffer buffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[4];
        buffer.get(magic);
        int version = Short.toUnsignedInt(buffer.getShort());
        int flags = Short.toUnsignedInt(buffer.getShort());
        byte[] txn = new byte[16];
        buffer.get(txn);
        byte[] baseFileId = new byte[16];
        buffer.get(baseFileId);
        byte[] newHeader = new byte[HEADER_SIZE];
        buffer.get(newHeader);
        int recordCount = buffer.getInt();
        int recordBytes = buffer.getInt();
        if (!Arrays.equals(magic, WAL_MAGIC) || version != WAL_VERSION
                || (flags & ~WAL_FLAG_FULL) != 0 || recordCount < 0
                || recordBytes < 0) {
            throw new WalInvalidException("bad WAL header");
        }
        ByteBuffer fileHeader = ByteBuffer.wrap(newHeader)
                .order(ByteOrder.LITTLE_ENDIAN);
        int chunkSize = fileHeader.getInt(24);
        long plaintextLength = fileHeader.getLong(28);
        int chunkCount = fileHeader.getInt(36);
        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE
                || (chunkSize & (chunkSize - 1)) != 0
                || plaintextLength < 0 || plaintextLength > MAX_LENGTH
                || chunkCount < 0
                || chunkCount != chunksFor(plaintextLength, chunkSize)
                || recordCount != recordBytes / (chunkSize + WAL_RECORD_OVERHEAD)
                || recordBytes != recordCount * (chunkSize + WAL_RECORD_OVERHEAD)
                || size != (long) WAL_HEADER_SIZE + recordBytes + WAL_FOOTER_SIZE) {
            throw new WalInvalidException("bad WAL geometry");
        }
        byte[] actual = sha256(wal, size - WAL_FOOTER_SIZE);
        try (RandomAccessFile input = new RandomAccessFile(wal, "r")) {
            input.seek(size - WAL_FOOTER_SIZE);
            byte[] footer = new byte[WAL_FOOTER_SIZE];
            input.readFully(footer);
            ByteBuffer tail = ByteBuffer.wrap(footer)
                    .order(ByteOrder.LITTLE_ENDIAN);
            byte[] footerMagic = new byte[4];
            tail.get(footerMagic);
            byte[] footerTxn = new byte[16];
            tail.get(footerTxn);
            byte[] digest = new byte[32];
            tail.get(digest);
            if (!Arrays.equals(footerMagic, WAL_MAGIC)
                    || !Arrays.equals(footerTxn, txn)
                    || !Arrays.equals(actual, digest)) {
                throw new WalInvalidException("bad WAL footer");
            }
        }
        byte[] nonce = Arrays.copyOfRange(newHeader, 40, 52);
        byte[] tag = Arrays.copyOfRange(newHeader, 52, 68);
        try {
            byte[] empty = ShieldCrypto.gcmDecrypt(key, nonce, tag,
                    Arrays.copyOfRange(newHeader, 0, 52));
            if (empty.length != 0) {
                throw new WalInvalidException("bad WAL file header tag");
            }
        } catch (IOException error) {
            throw new WalInvalidException("bad WAL file header tag");
        } catch (Exception error) {
            throw new WalInvalidException("bad WAL file header tag");
        }
        return new WalInfo(newHeader, baseFileId, txn, chunkSize, plaintextLength,
                chunkCount, recordCount, recordBytes,
                (flags & WAL_FLAG_FULL) != 0);
    }

    static void applyWalFile(File target, File wal, byte[] key) throws IOException {
        WalInfo info = readWalInfo(wal, key);
        if (!info.full) {
            byte[] targetFileId = targetFileId(target, key);
            if (targetFileId == null
                    || !Arrays.equals(targetFileId, info.baseFileId)) {
                throw new WalInvalidException("WAL base mismatch");
            }
        }
        boolean[] seen = new boolean[info.chunkCount];
        try (RandomAccessFile input = new RandomAccessFile(wal, "r")) {
            input.seek(WAL_HEADER_SIZE);
            for (int record = 0; record < info.recordCount; record++) {
                int index = readLeInt(input);
                int length = readLeInt(input);
                if (index < 0 || index >= info.chunkCount || seen[index]
                        || length != Math.min(info.chunkSize,
                        info.plaintextLength - (long) index * info.chunkSize)) {
                    throw new WalInvalidException("bad WAL record");
                }
                byte[] nonce = new byte[NONCE_SIZE];
                input.readFully(nonce);
                byte[] ciphertext = new byte[info.chunkSize + TAG_SIZE];
                input.readFully(ciphertext);
                try {
                    byte[] plaintext = ShieldCrypto.gcmDecrypt(key, nonce,
                            ciphertext, walChunkAad(info.fileId, index, length));
                    if (plaintext.length != info.chunkSize) {
                        throw new WalInvalidException("bad WAL chunk length");
                    }
                } catch (IOException error) {
                    throw new WalInvalidException("bad WAL chunk");
                } catch (Exception error) {
                    throw new WalInvalidException("bad WAL chunk");
                }
                seen[index] = true;
            }
        }
        if (info.full) {
            for (boolean value : seen) {
                if (!value) {
                    throw new WalInvalidException("incomplete full WAL");
                }
            }
        }
        long expectedSize = HEADER_SIZE
                + (long) info.chunkCount * (info.chunkSize + RECORD_OVERHEAD);
        try (RandomAccessFile output = new RandomAccessFile(target, "rw")) {
            output.seek(0);
            output.write(info.newHeader);
            try (RandomAccessFile input = new RandomAccessFile(wal, "r")) {
                input.seek(WAL_HEADER_SIZE);
                for (int record = 0; record < info.recordCount; record++) {
                    int index = readLeInt(input);
                    readLeInt(input);
                    byte[] nonce = new byte[NONCE_SIZE];
                    input.readFully(nonce);
                    byte[] ciphertext = new byte[info.chunkSize + TAG_SIZE];
                    input.readFully(ciphertext);
                    long offset = HEADER_SIZE
                            + (long) index * (info.chunkSize + RECORD_OVERHEAD);
                    output.seek(offset);
                    output.write(nonce);
                    output.write(ciphertext);
                }
            }
            output.setLength(expectedSize);
            output.getFD().sync();
        }
        fsyncDirectory(target.getParentFile());
        deleteQuietly(wal);
        fsyncDirectory(target.getParentFile());
    }

    private static int readLeInt(RandomAccessFile input) throws IOException {
        byte[] value = new byte[4];
        input.readFully(value);
        return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static byte[] targetFileId(File target, byte[] key) {
        if (!hasMagic(target)) {
            return null;
        }
        try (RandomAccessFile input = new RandomAccessFile(target, "r")) {
            byte[] header = new byte[HEADER_SIZE];
            input.readFully(header);
            byte[] nonce = Arrays.copyOfRange(header, 40, 52);
            byte[] tag = Arrays.copyOfRange(header, 52, 68);
            byte[] empty = ShieldCrypto.gcmDecrypt(key, nonce, tag,
                    Arrays.copyOfRange(header, 0, 52));
            if (empty.length != 0) {
                return null;
            }
            return Arrays.copyOfRange(header, 8, 24);
        } catch (Exception error) {
            return null;
        }
    }

    private static byte[] walChunkAad(byte[] fileId, int index, int chunkLength) {
        ByteBuffer buffer = ByteBuffer.allocate(AAD_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MAGIC);
        buffer.putShort((short) VERSION);
        buffer.put(fileId);
        buffer.putInt(index);
        buffer.putInt(chunkLength);
        return buffer.array();
    }

    private static void moveAtomic(File source, File target) throws IOException {
        try {
            Files.move(source.toPath(), target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException moveFailure) {
            if (!source.renameTo(target)) {
                throw moveFailure;
            }
        }
    }

    private void recover(File target) throws IOException {
        File commit = commit(target);
        File image = temp(target);
        if (commit.isFile()) {
            CommitInfo info = readCommit(commit);
            if (info != null) {
                if (image.isFile() && hasMagic(image)
                        && image.length() == info.imageLength
                        && Arrays.equals(sha256(image), info.digest)) {
                    moveAtomic(image, target);
                    fsyncDirectory(target.getParentFile());
                    deleteQuietly(commit);
                    fsyncDirectory(target.getParentFile());
                }
                if (target.isFile() && hasMagic(target)
                        && target.length() == info.imageLength
                        && Arrays.equals(sha256(target), info.digest)) {
                    deleteQuietly(image);
                    deleteQuietly(commit);
                    fsyncDirectory(target.getParentFile());
                }
            }
            // No usable image or already-applied target: roll the journal back.
            deleteQuietly(commit);
            deleteQuietly(image);
            fsyncDirectory(target.getParentFile());
        }
        File wal = wal(target);
        if (wal.isFile()) {
            try {
                applyWalFile(target, wal, key);
            } catch (WalInvalidException invalid) {
                deleteQuietly(wal);
                fsyncDirectory(target.getParentFile());
            }
        }
        deleteStaleTemp(target);
        deleteQuietly(commitTemp(target));
        deleteQuietly(walTemp(target));
    }

    private static CommitInfo readCommit(File commit) {
        if (commit.length() != JOURNAL_SIZE) {
            return null;
        }
        try (InputStream input = new FileInputStream(commit)) {
            byte[] data = new byte[JOURNAL_SIZE];
            int offset = 0;
            while (offset < data.length) {
                int read = input.read(data, offset, data.length - offset);
                if (read < 0) {
                    return null;
                }
                offset += read;
            }
            ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic = new byte[4];
            buffer.get(magic);
            if (!Arrays.equals(magic, JOURNAL_MAGIC)
                    || Short.toUnsignedInt(buffer.getShort()) != JOURNAL_VERSION) {
                return null;
            }
            buffer.get();
            buffer.get();
            byte[] txn = new byte[16];
            buffer.get(txn);
            long imageLength = buffer.getLong();
            long plaintextLength = buffer.getLong();
            byte[] fileId = new byte[16];
            buffer.get(fileId);
            byte[] digest = new byte[32];
            buffer.get(digest);
            byte[] footer = new byte[4];
            buffer.get(footer);
            byte[] footerTxn = new byte[16];
            buffer.get(footerTxn);
            buffer.getInt();
            if (!Arrays.equals(footer, JOURNAL_MAGIC)
                    || !Arrays.equals(txn, footerTxn)
                    || imageLength < HEADER_SIZE
                    || plaintextLength < 0) {
                return null;
            }
            return new CommitInfo(imageLength, plaintextLength, fileId, digest);
        } catch (IOException error) {
            return null;
        }
    }

    static void writeCommitFile(File target, long imageLength, long plaintextLength,
                                byte[] fileId, byte[] digest) throws IOException {
        if (fileId.length != 16 || digest.length != 32) {
            throw new IOException("invalid journal fields");
        }
        byte[] txn = new byte[16];
        RANDOM.nextBytes(txn);
        ByteBuffer buffer = ByteBuffer.allocate(JOURNAL_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(JOURNAL_MAGIC);
        buffer.putShort((short) JOURNAL_VERSION);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put(txn);
        buffer.putLong(imageLength);
        buffer.putLong(plaintextLength);
        buffer.put(fileId);
        buffer.put(digest);
        buffer.put(JOURNAL_MAGIC);
        buffer.put(txn);
        buffer.putInt(0);
        File commitTemp = commitTemp(target);
        try (RandomAccessFile output = new RandomAccessFile(commitTemp, "rw")) {
            output.setLength(0);
            output.write(buffer.array());
            output.getFD().sync();
        } catch (IOException error) {
            //noinspection ResultOfMethodCallIgnored
            commitTemp.delete();
            throw error;
        }
        moveAtomic(commitTemp, commit(target));
        fsyncDirectory(target.getParentFile());
    }

    private static boolean hasMagic(File file) {
        if (!file.isFile() || file.length() < MAGIC.length) {
            return false;
        }
        try (InputStream input = new FileInputStream(file)) {
            byte[] magic = new byte[MAGIC.length];
            return input.read(magic) == magic.length && Arrays.equals(magic, MAGIC);
        } catch (IOException error) {
            return false;
        }
    }

    private static byte[] sha256(File file, long length) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception error) {
            throw new IOException("SHA-256 unavailable", error);
        }
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            long remaining = length;
            while (remaining > 0) {
                int read = input.read(buffer, 0,
                        (int) Math.min(buffer.length, remaining));
                if (read < 0) {
                    throw new IOException("short WAL read");
                }
                digest.update(buffer, 0, read);
                remaining -= read;
            }
        }
        return digest.digest();
    }

    private static byte[] sha256(File file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception error) {
            throw new IOException("SHA-256 unavailable", error);
        }
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
        }
        return digest.digest();
    }

    private static void fsyncDirectory(File directory) {
        if (directory == null) {
            return;
        }
        try (FileChannel channel = FileChannel.open(directory.toPath(),
                StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException ignored) {
            // Some ROMs/filesystems do not allow opening a directory.
        }
    }

    private static void deleteQuietly(File file) {
        if (file != null && file.isFile()) {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        }
    }

    static final class WalInvalidException extends IOException {
        WalInvalidException(String message) {
            super(message);
        }
    }

    static final class WalInfo {
        final byte[] newHeader;
        final byte[] fileId;
        final byte[] baseFileId;
        final byte[] txn;
        final int chunkSize;
        final long plaintextLength;
        final int chunkCount;
        final int recordCount;
        final int recordBytes;
        final boolean full;

        WalInfo(byte[] newHeader, byte[] baseFileId, byte[] txn, int chunkSize,
                long plaintextLength, int chunkCount, int recordCount,
                int recordBytes, boolean full) {
            this.newHeader = newHeader;
            this.fileId = Arrays.copyOfRange(newHeader, 8, 24);
            this.baseFileId = baseFileId;
            this.txn = txn;
            this.chunkSize = chunkSize;
            this.plaintextLength = plaintextLength;
            this.chunkCount = chunkCount;
            this.recordCount = recordCount;
            this.recordBytes = recordBytes;
            this.full = full;
        }
    }

    private static final class CommitInfo {
        final long imageLength;
        final long plaintextLength;
        final byte[] fileId;
        final byte[] digest;

        CommitInfo(long imageLength, long plaintextLength, byte[] fileId,
                   byte[] digest) {
            this.imageLength = imageLength;
            this.plaintextLength = plaintextLength;
            this.fileId = fileId;
            this.digest = digest;
        }
    }

    int chunkSize() {
        return chunkSize;
    }

    byte[] fileIdCopy() {
        return Arrays.copyOf(fileId, 16);
    }

    static byte[] fileIdOf(File target, byte[] key) {
        try (ShieldChunkStore store = new ShieldChunkStore(target, key, "r", false)) {
            return store.fileIdCopy();
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    byte[] readAllBytes() throws IOException {
        ensureOpen();
        if (length > MAX_LENGTH) {
            throw new IOException("file too large");
        }
        byte[] data = new byte[(int) length];
        int offset = 0;
        while (offset < data.length) {
            int read = read(offset, data, offset, data.length - offset);
            if (read < 0) {
                break;
            }
            offset += read;
        }
        return data;
    }

    static byte[][] chunkHashes(byte[] data, int chunkSize) {
        int count = chunksFor(data.length, chunkSize);
        byte[][] hashes = new byte[count][];
        for (int index = 0; index < count; index++) {
            int offset = index * chunkSize;
            hashes[index] = hashChunk(data, offset,
                    Math.min(chunkSize, data.length - offset), chunkSize);
        }
        return hashes;
    }

    private static byte[] hashChunk(byte[] data, int offset, int length,
                                    int chunkSize) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data, offset, length);
            if (length < chunkSize) {
                byte[] padding = new byte[chunkSize - length];
                digest.update(padding);
            }
            return digest.digest();
        } catch (Exception error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    static final class MergeResult {
        final boolean merged;
        final int conflicts;
        final int written;

        MergeResult(boolean merged, int conflicts, int written) {
            this.merged = merged;
            this.conflicts = conflicts;
            this.written = written;
        }
    }

    static MergeResult writeMerged(File target, byte[] key, byte[] plaintext,
                                   byte[] baselineFileId, int baselineChunkSize,
                                   int baselineLength, byte[][] baselineHashes)
            throws IOException {
        if (plaintext.length > MAX_LENGTH || baselineFileId == null
                || baselineHashes == null || baselineChunkSize <= 0
                || !target.isFile() || !matches(target)) {
            writeAll(target, key, plaintext);
            return new MergeResult(false, 0, 0);
        }
        try (ShieldChunkStore store =
                     new ShieldChunkStore(target, key, "rw", false)) {
            if (store.chunkSize != baselineChunkSize
                    || !Arrays.equals(store.fileId, baselineFileId)) {
                store.replaceAll(plaintext);
                return new MergeResult(false, 1, 0);
            }
            return store.merge(plaintext, baselineLength, baselineHashes);
        } catch (IOException | RuntimeException error) {
            writeAll(target, key, plaintext);
            return new MergeResult(false, 0, 0);
        }
    }

    private MergeResult merge(byte[] plaintext, int baselineLength,
                              byte[][] baselineHashes) throws IOException {
        long targetLength = length;
        int targetCount = chunksFor(targetLength, chunkSize);
        int localCount = chunksFor(plaintext.length, chunkSize);
        boolean localLengthChanged = plaintext.length != baselineLength;
        boolean remoteLengthChanged = targetLength != baselineLength;
        int conflicts = 0;
        List<Integer> writes = new ArrayList<>();
        byte[] targetChunk = new byte[chunkSize];
        for (int index = 0; index < localCount; index++) {
            int offset = index * chunkSize;
            int localLength = Math.min(chunkSize, plaintext.length - offset);
            byte[] localHash = hashChunk(plaintext, offset, localLength, chunkSize);
            byte[] baseHash = index < baselineHashes.length
                    ? baselineHashes[index] : null;
            if (baseHash != null && Arrays.equals(localHash, baseHash)) {
                continue;
            }
            boolean remoteChanged = false;
            if (index < targetCount) {
                int targetRemaining = (int) (targetLength - offset);
                int targetLen = Math.min(chunkSize, targetRemaining);
                Arrays.fill(targetChunk, (byte) 0);
                int read = read(offset, targetChunk, 0, targetLen);
                if (read < 0) {
                    Arrays.fill(targetChunk, (byte) 0);
                }
                byte[] targetHash = hashChunk(targetChunk, 0, targetLen, chunkSize);
                remoteChanged = baseHash == null
                        || !Arrays.equals(targetHash, baseHash);
            } else if (!localLengthChanged) {
                // Remote truncated a region this writer did not resize.
                conflicts++;
                continue;
            }
            if (remoteChanged) {
                conflicts++;
            }
            writes.add(index);
        }
        if (localLengthChanged) {
            if (remoteLengthChanged && targetLength != plaintext.length) {
                conflicts++;
            }
            setLength(plaintext.length);
        }
        int written = 0;
        for (int index : writes) {
            int offset = index * chunkSize;
            int localLength = Math.min(chunkSize, plaintext.length - offset);
            write(offset, plaintext, offset, localLength);
            written++;
        }
        changed = written > 0 || (localLengthChanged && targetLength != plaintext.length);
        return new MergeResult(true, conflicts, written);
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

    private static File commit(File target) {
        return new File(target.getParentFile(), target.getName() + ".fmf2.commit");
    }

    private static File commitTemp(File target) {
        return new File(target.getParentFile(), target.getName() + ".fmf2.commit.tmp");
    }

    private static File wal(File target) {
        return new File(target.getParentFile(), target.getName() + ".fmf2.wal");
    }

    private static File walTemp(File target) {
        return new File(target.getParentFile(), target.getName() + ".fmf2.wal.tmp");
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
