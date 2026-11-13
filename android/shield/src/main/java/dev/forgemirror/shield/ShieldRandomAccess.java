package dev.forgemirror.shield;

import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import java.io.Closeable;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

/**
 * Random-access view over an encrypted file. FMF2 files use chunked AEAD and
 * touch only the modified chunks on persist; legacy FMF1/plaintext files are
 * read through an in-memory view and migrate to FMF2 on the first write.
 *
 * Android's RandomAccessFile marks its I/O methods final, so this is a
 * composed type implementing DataInput/DataOutput rather than a subclass.
 * mmap, file descriptors and cross-process writes are not covered.
 */
public final class ShieldRandomAccess implements DataInput, DataOutput, Closeable {
    private static final int MAX_BUFFER = 64 << 20;

    private final File target;
    private final byte[] key;
    private final boolean encrypted;
    private final boolean writable;
    private final ShieldChunkStore store;
    private final DataInputStream input;
    private final DataOutputStream output;

    private byte[] data;
    private long length;
    private long pointer;
    private boolean dirty;
    private boolean closed;
    private FileDescriptor snapshotDescriptor;

    ShieldRandomAccess(File target, byte[] key, String mode) throws IOException {
        this(target, key, mode, true);
    }

    static ShieldRandomAccess plain(File target, String mode)
            throws FileNotFoundException {
        try {
            return new ShieldRandomAccess(target, null, mode, false);
        } catch (IOException error) {
            FileNotFoundException failure = new FileNotFoundException(target.getPath());
            failure.initCause(error);
            throw failure;
        }
    }

    ShieldRandomAccess(File target, byte[] key, String mode, boolean encrypted)
            throws IOException {
        if (!"r".equals(mode) && !"rw".equals(mode)
                && !"rws".equals(mode) && !"rwd".equals(mode)) {
            throw new IllegalArgumentException("unsupported mode: " + mode);
        }
        this.target = target;
        this.key = key;
        this.encrypted = encrypted;
        this.writable = !"r".equals(mode);
        if (!writable && !target.isFile()) {
            throw new FileNotFoundException(target.getPath());
        }
        if (encrypted && (!target.isFile() || ShieldChunkStore.matches(target))) {
            this.store = ShieldChunkStore.open(target, key, mode);
            this.length = store.length();
            this.data = null;
        } else {
            this.store = null;
            byte[] plaintext = target.isFile() ? readPlaintext() : new byte[0];
            if (plaintext.length > MAX_BUFFER) {
                throw new IOException("file too large for random-access buffer");
            }
            this.data = new byte[Math.max(64, plaintext.length)];
            System.arraycopy(plaintext, 0, data, 0, plaintext.length);
            this.length = plaintext.length;
            this.dirty = writable && !target.isFile();
        }

        InputStream reader = new InputStream() {
            @Override
            public int read() throws IOException {
                return readRawByte();
            }

            @Override
            public int read(byte[] buffer, int offset, int count) throws IOException {
                return readRaw(buffer, offset, count);
            }

            @Override
            public long skip(long count) {
                try {
                    long skipped = Math.min(Math.max(count, 0),
                            Math.max(0, length() - pointer));
                    pointer += skipped;
                    return skipped;
                } catch (IOException error) {
                    return 0;
                }
            }

            @Override
            public int available() {
                try {
                    return (int) Math.min(Math.max(0, length() - pointer),
                            Integer.MAX_VALUE);
                } catch (IOException error) {
                    return 0;
                }
            }
        };
        OutputStream writer = new OutputStream() {
            @Override
            public void write(int oneByte) throws IOException {
                writeRawByte(oneByte);
            }

            @Override
            public void write(byte[] buffer, int offset, int count) throws IOException {
                writeRaw(buffer, offset, count);
            }
        };
        this.input = new DataInputStream(reader);
        this.output = new DataOutputStream(writer);
    }

    private byte[] readPlaintext() throws IOException {
        byte[] blob = new byte[(int) target.length()];
        try (java.io.FileInputStream in = new java.io.FileInputStream(target)) {
            int offset = 0;
            while (offset < blob.length) {
                int read = in.read(blob, offset, blob.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        }
        if (!encrypted || !ShieldCrypto.isFileEncrypted(blob)) {
            return blob;
        }
        try {
            return ShieldCrypto.fileDecrypt(blob, key);
        } catch (Exception error) {
            throw new IOException("encrypted file rejected: " + target, error);
        }
    }

    private int readRawByte() throws IOException {
        ensureOpen();
        if (store != null) {
            byte[] one = new byte[1];
            int read = store.read(pointer, one, 0, 1);
            if (read < 0) {
                return -1;
            }
            pointer += read;
            return one[0] & 0xff;
        }
        if (pointer >= length) {
            return -1;
        }
        return data[(int) pointer++] & 0xff;
    }

    private int readRaw(byte[] buffer, int offset, int count) throws IOException {
        ensureOpen();
        if (count == 0) {
            return 0;
        }
        if (store != null) {
            int read = store.read(pointer, buffer, offset, count);
            if (read > 0) {
                pointer += read;
            }
            return read;
        }
        if (pointer >= length) {
            return -1;
        }
        int read = (int) Math.min(count, length - pointer);
        System.arraycopy(data, (int) pointer, buffer, offset, read);
        pointer += read;
        return read;
    }

    private void writeRawByte(int oneByte) throws IOException {
        ensureWritable();
        if (store != null) {
            store.write(pointer, new byte[]{(byte) oneByte}, 0, 1);
            pointer++;
            return;
        }
        ensureCapacity(pointer + 1);
        data[(int) pointer++] = (byte) oneByte;
        length = Math.max(length, pointer);
        dirty = true;
    }

    private void writeRaw(byte[] buffer, int offset, int count) throws IOException {
        ensureWritable();
        if (store != null) {
            store.write(pointer, buffer, offset, count);
            pointer += count;
            return;
        }
        ensureCapacity(pointer + count);
        System.arraycopy(buffer, offset, data, (int) pointer, count);
        pointer += count;
        length = Math.max(length, pointer);
        dirty = true;
    }

    public int read(byte[] buffer) throws IOException {
        return readRaw(buffer, 0, buffer.length);
    }

    public int read(byte[] buffer, int offset, int count) throws IOException {
        return readRaw(buffer, offset, count);
    }

    public long getFilePointer() throws IOException {
        ensureOpen();
        return pointer;
    }

    public void seek(long position) throws IOException {
        ensureOpen();
        if (position < 0 || position > maxLength()) {
            throw new IOException("invalid seek position: " + position);
        }
        pointer = position;
    }

    public long length() throws IOException {
        ensureOpen();
        return store != null ? store.length() : length;
    }

    /**
     * Returns a duplicated read-only descriptor for a plaintext snapshot in an
     * anonymous memfd. The caller owns and must close it. Changes made through
     * the descriptor are not written back to the encrypted file.
     */
    public FileDescriptor getFD() throws IOException {
        ensureOpen();
        try {
            return Os.dup(snapshotDescriptor());
        } catch (ErrnoException error) {
            throw new IOException("descriptor duplication failed", error);
        }
    }

    /** Returns a channel over a plaintext snapshot; see {@link #getFD()}. */
    public FileChannel getChannel() throws IOException {
        ensureOpen();
        try {
            return new java.io.FileInputStream(Os.dup(snapshotDescriptor())).getChannel();
        } catch (ErrnoException error) {
            throw new IOException("channel snapshot failed", error);
        }
    }

    private synchronized FileDescriptor snapshotDescriptor() throws IOException {
        if (snapshotDescriptor != null) {
            return snapshotDescriptor;
        }
        if (Build.VERSION.SDK_INT < 27) {
            throw new IOException("memfd requires API 27");
        }
        long total = store != null ? store.length() : length;
        if (total > Integer.MAX_VALUE) {
            throw new IOException("file too large for snapshot");
        }
        byte[] plaintext = new byte[(int) total];
        long saved = pointer;
        try {
            pointer = 0;
            int offset = 0;
            while (offset < plaintext.length) {
                int read = readRaw(plaintext, offset, plaintext.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        } finally {
            pointer = saved;
        }
        try {
            FileDescriptor descriptor = Os.memfd_create("forgemirror", 0);
            int offset = 0;
            while (offset < plaintext.length) {
                int written = Os.write(descriptor, plaintext, offset,
                        plaintext.length - offset);
                if (written <= 0) {
                    throw new IOException("memfd write stalled");
                }
                offset += written;
            }
            Os.lseek(descriptor, 0, android.system.OsConstants.SEEK_SET);
            snapshotDescriptor = descriptor;
            return descriptor;
        } catch (ErrnoException error) {
            throw new IOException("memfd snapshot failed", error);
        }
    }

    public void setLength(long newLength) throws IOException {
        ensureWritable();
        if (newLength < 0 || newLength > maxLength()) {
            throw new IOException("invalid length: " + newLength);
        }
        if (store != null) {
            store.setLength(newLength);
        } else {
            ensureCapacity(newLength);
            if (newLength < length) {
                Arrays.fill(data, (int) newLength, (int) length, (byte) 0);
            }
            length = newLength;
            dirty = true;
        }
        if (pointer > newLength) {
            pointer = newLength;
        }
    }

    @Override
    public void readFully(byte[] buffer) throws IOException {
        input.readFully(buffer);
    }

    @Override
    public void readFully(byte[] buffer, int offset, int count) throws IOException {
        input.readFully(buffer, offset, count);
    }

    @Override
    public int skipBytes(int count) throws IOException {
        ensureOpen();
        int skipped = (int) Math.min(Math.max(count, 0), Math.max(0, length() - pointer));
        pointer += skipped;
        return skipped;
    }

    @Override
    public boolean readBoolean() throws IOException {
        return input.readBoolean();
    }

    @Override
    public byte readByte() throws IOException {
        return input.readByte();
    }

    @Override
    public int readUnsignedByte() throws IOException {
        return input.readUnsignedByte();
    }

    @Override
    public short readShort() throws IOException {
        return input.readShort();
    }

    @Override
    public int readUnsignedShort() throws IOException {
        return input.readUnsignedShort();
    }

    @Override
    public char readChar() throws IOException {
        return input.readChar();
    }

    @Override
    public int readInt() throws IOException {
        return input.readInt();
    }

    @Override
    public long readLong() throws IOException {
        return input.readLong();
    }

    @Override
    public float readFloat() throws IOException {
        return input.readFloat();
    }

    @Override
    public double readDouble() throws IOException {
        return input.readDouble();
    }

    @Deprecated
    @Override
    public String readLine() throws IOException {
        return input.readLine();
    }

    @Override
    public String readUTF() throws IOException {
        return input.readUTF();
    }

    @Override
    public void write(int oneByte) throws IOException {
        writeRawByte(oneByte);
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        writeRaw(buffer, 0, buffer.length);
    }

    @Override
    public void write(byte[] buffer, int offset, int count) throws IOException {
        writeRaw(buffer, offset, count);
    }

    @Override
    public void writeBoolean(boolean value) throws IOException {
        output.writeBoolean(value);
    }

    @Override
    public void writeByte(int value) throws IOException {
        output.writeByte(value);
    }

    @Override
    public void writeShort(int value) throws IOException {
        output.writeShort(value);
    }

    @Override
    public void writeChar(int value) throws IOException {
        output.writeChar(value);
    }

    @Override
    public void writeInt(int value) throws IOException {
        output.writeInt(value);
    }

    @Override
    public void writeLong(long value) throws IOException {
        output.writeLong(value);
    }

    @Override
    public void writeFloat(float value) throws IOException {
        output.writeFloat(value);
    }

    @Override
    public void writeDouble(double value) throws IOException {
        output.writeDouble(value);
    }

    @Override
    public void writeBytes(String value) throws IOException {
        output.writeBytes(value);
    }

    @Override
    public void writeChars(String value) throws IOException {
        output.writeChars(value);
    }

    @Override
    public void writeUTF(String value) throws IOException {
        output.writeUTF(value);
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (store != null) {
                store.close();
                return;
            }
            if (writable && dirty) {
                byte[] plaintext = Arrays.copyOf(data, (int) length);
                if (encrypted) {
                    ShieldChunkStore.writeAll(target, key, plaintext);
                } else {
                    writeAtomic(plaintext);
                }
            }
        } catch (Exception error) {
            throw new IOException("persist failed: " + target, error);
        } finally {
            if (snapshotDescriptor != null) {
                try {
                    Os.close(snapshotDescriptor);
                } catch (ErrnoException ignored) {
                    // Best effort.
                }
                snapshotDescriptor = null;
            }
        }
    }

    private void writeAtomic(byte[] blob) throws IOException {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create " + parent);
        }
        File temp = temp(target);
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(temp)) {
            out.write(blob);
            out.getFD().sync();
        }
        try {
            Files.move(temp.toPath(), target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException moveFailure) {
            if (!temp.renameTo(target)) {
                throw new IOException("atomic move failed: " + target, moveFailure);
            }
        }
    }

    private void ensureCapacity(long required) throws IOException {
        if (required > MAX_BUFFER) {
            throw new IOException("file too large for random-access buffer");
        }
        if (required <= data.length) {
            return;
        }
        int capacity = data.length;
        while (capacity < required) {
            capacity = capacity < 1 << 20 ? capacity * 2 : capacity + (1 << 20);
        }
        data = Arrays.copyOf(data, Math.min(capacity, MAX_BUFFER));
    }

    private long maxLength() {
        return store != null ? ShieldChunkStore.MAX_LENGTH : MAX_BUFFER;
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

    private static File temp(File target) {
        return new File(target.getParentFile(), target.getName() + ".tmp");
    }
}
