package dev.forgemirror.shield;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

public final class ShieldChunkStoreTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private static final byte[] KEY = new byte[32];

    static {
        for (int index = 0; index < KEY.length; index++) {
            KEY[index] = (byte) (index + 1);
        }
    }

    private File file() throws IOException {
        return folder.newFile();
    }

    private static byte[] pattern(int length, int seed) {
        byte[] data = new byte[length];
        for (int index = 0; index < length; index++) {
            data[index] = (byte) ((index * 31 + seed) & 0xff);
        }
        return data;
    }

    private static void writeBlocks(ShieldChunkStore store, byte[] data) throws IOException {
        int offset = 0;
        while (offset < data.length) {
            int count = Math.min(65536, data.length - offset);
            store.write(offset, data, offset, count);
            offset += count;
        }
    }

    private static byte[] readAll(File file) throws IOException {
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "r")) {
            long length = store.length();
            byte[] data = new byte[(int) length];
            int offset = 0;
            while (offset < length) {
                int read = store.read(offset, data, offset, (int) (length - offset));
                if (read < 0) {
                    break;
                }
                offset += read;
            }
            assertEquals(length, offset);
            return data;
        }
    }

    @Test
    public void roundTripChunked() throws Exception {
        File file = file();
        byte[] data = pattern(200000, 7);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        assertTrue(ShieldChunkStore.matches(file));
        assertArrayEquals(data, readAll(file));
    }

    @Test
    public void randomWriteAcrossChunkBoundary() throws Exception {
        File file = file();
        byte[] data = pattern(150000, 3);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        byte[] patch = pattern(32, 99);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            store.write(65530, patch, 0, patch.length);
        }
        byte[] expected = data.clone();
        System.arraycopy(patch, 0, expected, 65530, patch.length);
        assertArrayEquals(expected, readAll(file));
    }

    @Test
    public void shrinkThenGrowDoesNotResurrect() throws Exception {
        File file = file();
        byte[] data = pattern(200000, 5);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            store.setLength(1000);
        }
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            store.setLength(200000);
        }
        byte[] grown = readAll(file);
        assertEquals(200000, grown.length);
        for (int index = 1000; index < grown.length; index++) {
            if (grown[index] != 0) {
                fail("stale byte resurrected at " + index);
            }
        }
    }

    @Test
    public void shrinkThenGrowWithinSessionDoesNotResurrect() throws Exception {
        File file = file();
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, pattern(200000, 5));
            store.setLength(1000);
            store.setLength(200000);
        }
        byte[] grown = readAll(file);
        assertEquals(200000, grown.length);
        assertEquals(5, grown[0] & 0xff);
        for (int index = 1000; index < grown.length; index++) {
            if (grown[index] != 0) {
                fail("stale byte resurrected at " + index);
            }
        }
    }

    @Test
    public void rewriteRotatesChunkNonce() throws Exception {
        File file = file();
        byte[] data = pattern(1000, 1);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        byte[] firstNonce = readNonce(file, 0);
        byte[] firstCiphertext = readRecord(file, 0);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            store.write(0, pattern(1000, 42), 0, 1000);
        }
        byte[] secondNonce = readNonce(file, 0);
        byte[] secondCiphertext = readRecord(file, 0);
        assertFalse(Arrays.equals(firstNonce, secondNonce));
        assertFalse(Arrays.equals(firstCiphertext, secondCiphertext));
    }

    @Test
    public void tamperedChunkRejected() throws Exception {
        File file = file();
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, pattern(1000, 2));
        }
        try (RandomAccessFile raw = new RandomAccessFile(file, "rw")) {
            long position = ShieldChunkStore.HEADER_SIZE + ShieldChunkStore.NONCE_SIZE + 100;
            raw.seek(position);
            int value = raw.read();
            raw.seek(position);
            raw.write(value ^ 0xff);
        }
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "r")) {
            store.read(0, new byte[1000], 0, 1000);
            fail("tampered chunk accepted");
        } catch (IOException expected) {
            // Rejected.
        }
    }

    @Test
    public void tamperedHeaderRejected() throws Exception {
        File file = file();
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, pattern(1000, 2));
        }
        try (RandomAccessFile raw = new RandomAccessFile(file, "rw")) {
            raw.seek(28);
            int value = raw.read();
            raw.seek(28);
            raw.write(value ^ 0x01);
        }
        try {
            ShieldChunkStore.open(file, KEY, "r").close();
            fail("tampered header accepted");
        } catch (IOException expected) {
            // Rejected.
        }
    }

    @Test
    public void truncatedFileIsRejected() throws Exception {
        File file = file();
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, pattern(1000, 4));
        }
        try (RandomAccessFile raw = new RandomAccessFile(file, "rw")) {
            raw.setLength(file.length() - 10);
        }
        try {
            ShieldChunkStore.open(file, KEY, "r").close();
            fail("truncated FMF2 accepted");
        } catch (IOException expected) {
            // Rejected.
        }
    }

    @Test
    public void staleTempFromCrashIsDiscarded() throws Exception {
        File file = new File(folder.getRoot(), "crash.bin");
        byte[] data = pattern(5000, 8);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        File temp = new File(file.getParentFile(), file.getName() + ".fmf2.tmp");
        try (FileOutputStream out = new FileOutputStream(temp)) {
            out.write(pattern(123, 77));
        }
        assertTrue(temp.isFile());
        assertArrayEquals(data, readAll(file));
        assertFalse(temp.isFile());
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            byte[] patch = pattern(32, 55);
            store.write(0, patch, 0, patch.length);
        }
        assertTrue(ShieldChunkStore.matches(file));
    }

    @Test
    public void secondWritableOpenIsRejectedThenReopens() throws Exception {
        File file = new File(folder.getRoot(), "locked.bin");
        byte[] data = pattern(1000, 6);
        ShieldChunkStore first = ShieldChunkStore.open(file, KEY, "rw");
        writeBlocks(first, data);
        try {
            ShieldChunkStore second = ShieldChunkStore.open(file, KEY, "rw");
            second.close();
            fail("concurrent writable open accepted");
        } catch (IOException expected) {
            // Rejected by the per-file lock.
        }
        first.close();
        assertArrayEquals(data, readAll(file));
    }

    @Test
    public void renamedFileKeepsContent() throws Exception {
        File file = new File(folder.getRoot(), "before.bin");
        File renamed = new File(folder.getRoot(), "after.bin");
        byte[] data = pattern(9000, 9);
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            writeBlocks(store, data);
        }
        Files.move(file.toPath(), renamed.toPath(),
                StandardCopyOption.ATOMIC_MOVE);
        assertArrayEquals(data, readAll(renamed));
    }

    @Test
    public void writeAllMigratesLegacyContent() throws Exception {
        File file = file();
        byte[] plaintext = pattern(70000, 11);
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(plaintext);
        }
        assertFalse(ShieldChunkStore.matches(file));
        ShieldChunkStore.writeAll(file, KEY, plaintext);
        assertTrue(ShieldChunkStore.matches(file));
        assertArrayEquals(plaintext, readAll(file));
    }

    @Test
    public void emptyFileHasHeaderOnly() throws Exception {
        File file = new File(folder.getRoot(), "empty.bin");
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "rw")) {
            assertEquals(0, store.length());
        }
        assertEquals(ShieldChunkStore.HEADER_SIZE, file.length());
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "r")) {
            assertEquals(0, store.length());
            assertEquals(-1, store.read(0, new byte[4], 0, 4));
        }
    }

    private static byte[] readNonce(File file, int index) throws IOException {
        try (RandomAccessFile raw = new RandomAccessFile(file, "r")) {
            byte[] nonce = new byte[ShieldChunkStore.NONCE_SIZE];
            raw.seek(ShieldChunkStore.HEADER_SIZE
                    + (long) index * (ShieldChunkStore.DEFAULT_CHUNK_SIZE
                    + ShieldChunkStore.NONCE_SIZE + ShieldChunkStore.TAG_SIZE));
            raw.readFully(nonce);
            return nonce;
        }
    }

    private static byte[] readRecord(File file, int index) throws IOException {
        try (RandomAccessFile raw = new RandomAccessFile(file, "r")) {
            byte[] record = new byte[64];
            raw.seek(ShieldChunkStore.HEADER_SIZE
                    + (long) index * (ShieldChunkStore.DEFAULT_CHUNK_SIZE
                    + ShieldChunkStore.NONCE_SIZE + ShieldChunkStore.TAG_SIZE));
            raw.readFully(record);
            return record;
        }
    }
}
