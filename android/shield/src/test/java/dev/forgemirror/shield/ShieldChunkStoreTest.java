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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
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

    private static byte[] readOpened(File file) throws Exception {
        try (ShieldChunkStore store = ShieldChunkStore.open(file, KEY, "r")) {
            long length = store.length();
            byte[] data = new byte[(int) length];
            int offset = 0;
            while (offset < length) {
                int read = store.read(offset, data, offset,
                        (int) (length - offset));
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
    public void fullWalReplayCreatesMissingTarget() throws Exception {
        File target = new File(folder.getRoot(), "wal-missing.bin");
        byte[] data = pattern(7000, 31);
        File wal = ShieldChunkStore.prepareWal(target, KEY, data, true);
        assertTrue(wal.isFile());
        assertFalse(target.isFile());
        assertArrayEquals(data, readOpened(target));
        assertFalse(wal.isFile());
    }

    @Test
    public void incrementalWalOnlyLogsDirtyChunks() throws Exception {
        File target = new File(folder.getRoot(), "wal-incremental.bin");
        byte[] original = pattern(200000, 32);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, original);
        }
        byte[] updated = original.clone();
        byte[] patch = pattern(100, 33);
        System.arraycopy(patch, 0, updated, 0, patch.length);
        File wal = ShieldChunkStore.prepareWalPatch(target, KEY, 0, patch);
        assertTrue(wal.length() < original.length);
        assertArrayEquals(updated, readAll(target));
        assertFalse(wal.isFile());
    }

    @Test
    public void corruptedWalRollsBack() throws Exception {
        File target = new File(folder.getRoot(), "wal-corrupt.bin");
        byte[] original = pattern(6000, 34);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, original);
        }
        File wal = ShieldChunkStore.prepareWal(target, KEY,
                pattern(8000, 35), true);
        try (RandomAccessFile raw = new RandomAccessFile(wal, "rw")) {
            raw.setLength(wal.length() - 8);
        }
        assertArrayEquals(original, readAll(target));
        assertFalse(wal.isFile());
    }

    @Test
    public void appliedWalLeftoverIsIdempotent() throws Exception {
        File target = new File(folder.getRoot(), "wal-applied.bin");
        byte[] data = pattern(5000, 36);
        File wal = ShieldChunkStore.prepareWal(target, KEY, data, true);
        File backup = new File(folder.getRoot(), "wal-backup.bin");
        Files.copy(wal.toPath(), backup.toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        ShieldChunkStore.applyWalFile(target, wal, KEY);
        Files.copy(backup.toPath(), wal.toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        assertArrayEquals(data, readAll(target));
        assertFalse(wal.isFile());
    }

    @Test
    public void committedJournalReplaysPreparedImage() throws Exception {
        File target = new File(folder.getRoot(), "journal.bin");
        byte[] first = pattern(8000, 21);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, first);
        }
        File prepared = new File(folder.getRoot(), "prepared.bin");
        byte[] second = pattern(12000, 22);
        try (ShieldChunkStore store = ShieldChunkStore.open(prepared, KEY, "rw")) {
            writeBlocks(store, second);
        }
        File image = new File(folder.getRoot(), "journal.bin.fmf2.tmp");
        Files.copy(prepared.toPath(), image.toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        ShieldChunkStore.writeCommitFile(target, image.length(), second.length,
                new byte[16], digest(image));
        assertArrayEquals(second, readAll(target));
        assertFalse(image.isFile());
        assertFalse(new File(folder.getRoot(), "journal.bin.fmf2.commit").isFile());
    }

    @Test
    public void readOnlyOpenReplaysCommittedJournal() throws Exception {
        File target = new File(folder.getRoot(), "readonly-journal.bin");
        byte[] first = pattern(2000, 27);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, first);
        }
        File prepared = new File(folder.getRoot(), "readonly-prepared.bin");
        byte[] second = pattern(3000, 28);
        try (ShieldChunkStore store = ShieldChunkStore.open(prepared, KEY, "rw")) {
            writeBlocks(store, second);
        }
        File image = new File(folder.getRoot(), "readonly-journal.bin.fmf2.tmp");
        Files.copy(prepared.toPath(), image.toPath(),
                StandardCopyOption.REPLACE_EXISTING);
        ShieldChunkStore.writeCommitFile(target, image.length(), second.length,
                new byte[16], digest(image));
        assertArrayEquals(second, readAll(target));
        assertFalse(image.isFile());
    }

    @Test
    public void appliedJournalIsCleanedWithoutReplay() throws Exception {
        File target = new File(folder.getRoot(), "applied.bin");
        byte[] data = pattern(4000, 23);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, data);
        }
        ShieldChunkStore.writeCommitFile(target, target.length(), data.length,
                new byte[16], digest(target));
        assertArrayEquals(data, readAll(target));
        assertFalse(new File(folder.getRoot(), "applied.bin.fmf2.commit").isFile());
    }

    @Test
    public void truncatedJournalImageRollsBack() throws Exception {
        File target = new File(folder.getRoot(), "rollback.bin");
        byte[] data = pattern(3000, 24);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, data);
        }
        File image = new File(folder.getRoot(), "rollback.bin.fmf2.tmp");
        try (FileOutputStream out = new FileOutputStream(image)) {
            out.write(pattern(100, 25));
        }
        ShieldChunkStore.writeCommitFile(target, image.length(), 3000,
                new byte[16], digest(image));
        assertArrayEquals(data, readAll(target));
        assertFalse(image.isFile());
        assertFalse(new File(folder.getRoot(), "rollback.bin.fmf2.commit").isFile());
    }

    @Test
    public void malformedJournalIsIgnored() throws Exception {
        File target = new File(folder.getRoot(), "malformed.bin");
        byte[] data = pattern(2500, 26);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            writeBlocks(store, data);
        }
        File commit = new File(folder.getRoot(), "malformed.bin.fmf2.commit");
        try (FileOutputStream out = new FileOutputStream(commit)) {
            out.write(new byte[]{1, 2, 3});
        }
        assertArrayEquals(data, readAll(target));
        assertFalse(commit.isFile());
    }

    private static byte[] digest(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
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

    private static byte[] prefix(byte[] data, int offset, int length) {
        return Arrays.copyOfRange(data, offset, offset + length);
    }

    @Test
    public void crossProcessMergePreservesDisjointChunks() throws Exception {
        File target = new File(folder.getRoot(), "merge-disjoint.bin");
        byte[] baselineData = pattern(200000, 51);
        ShieldChunkStore.writeAll(target, KEY, baselineData);
        int chunkSize;
        byte[] fileId;
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "r")) {
            chunkSize = store.chunkSize();
            fileId = store.fileIdCopy();
        }
        byte[][] baselineHashes =
                ShieldChunkStore.chunkHashes(baselineData, chunkSize);

        byte[] remotePatch = pattern(100, 52);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            store.write(2L * chunkSize, remotePatch, 0, remotePatch.length);
        }
        byte[] localData = baselineData.clone();
        byte[] localPatch = pattern(100, 53);
        System.arraycopy(localPatch, 0, localData, 0, localPatch.length);

        ShieldChunkStore.MergeResult result = ShieldChunkStore.writeMerged(
                target, KEY, localData, fileId, chunkSize,
                baselineData.length, baselineHashes);
        assertTrue(result.merged);
        assertEquals(0, result.conflicts);
        byte[] merged = readAll(target);
        assertArrayEquals(localPatch, prefix(merged, 0, localPatch.length));
        assertArrayEquals(remotePatch, prefix(merged,
                2 * chunkSize, remotePatch.length));
        assertEquals(baselineData[chunkSize + 10], merged[chunkSize + 10]);
    }

    @Test
    public void crossProcessMergeConflictKeepsLocalChunk() throws Exception {
        File target = new File(folder.getRoot(), "merge-conflict.bin");
        byte[] baselineData = pattern(150000, 54);
        ShieldChunkStore.writeAll(target, KEY, baselineData);
        int chunkSize;
        byte[] fileId;
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "r")) {
            chunkSize = store.chunkSize();
            fileId = store.fileIdCopy();
        }
        byte[][] baselineHashes =
                ShieldChunkStore.chunkHashes(baselineData, chunkSize);
        byte[] remotePatch = pattern(120, 55);
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "rw")) {
            store.write(0, remotePatch, 0, remotePatch.length);
        }
        byte[] localData = baselineData.clone();
        byte[] localPatch = pattern(120, 56);
        System.arraycopy(localPatch, 0, localData, 0, localPatch.length);
        ShieldChunkStore.MergeResult result = ShieldChunkStore.writeMerged(
                target, KEY, localData, fileId, chunkSize,
                baselineData.length, baselineHashes);
        assertTrue(result.conflicts > 0);
        assertArrayEquals(localPatch,
                prefix(readAll(target), 0, localPatch.length));
    }

    @Test
    public void mergePreservesRemoteGrowthWhenLocalLengthUnchanged() throws Exception {
        File target = new File(folder.getRoot(), "merge-grow.bin");
        byte[] baselineData = pattern(120000, 57);
        ShieldChunkStore.writeAll(target, KEY, baselineData);
        int chunkSize;
        byte[] fileId;
        try (ShieldChunkStore store = ShieldChunkStore.open(target, KEY, "r")) {
            chunkSize = store.chunkSize();
            fileId = store.fileIdCopy();
        }
        byte[][] baselineHashes =
                ShieldChunkStore.chunkHashes(baselineData, chunkSize);
        byte[] remoteData = pattern(180000, 58);
        System.arraycopy(baselineData, 0, remoteData, 0, baselineData.length);
        ShieldChunkStore.writeAll(target, KEY, remoteData);

        byte[] localData = baselineData.clone();
        byte[] localPatch = pattern(64, 59);
        System.arraycopy(localPatch, 0, localData, 0, localPatch.length);
        ShieldChunkStore.MergeResult result = ShieldChunkStore.writeMerged(
                target, KEY, localData, fileId, chunkSize,
                baselineData.length, baselineHashes);
        byte[] merged = readAll(target);
        assertEquals(remoteData.length, merged.length);
        assertArrayEquals(localPatch, prefix(merged, 0, localPatch.length));
        assertArrayEquals(prefix(remoteData, 150000, 100),
                prefix(merged, 150000, 100));
    }

    @Test
    public void writeAllUpdatesExistingChunksThroughWal() throws Exception {
        File target = new File(folder.getRoot(), "writeall-diff.bin");
        byte[] first = pattern(150000, 41);
        ShieldChunkStore.writeAll(target, KEY, first);
        byte[] second = first.clone();
        byte[] patch = pattern(64, 42);
        System.arraycopy(patch, 0, second, 70000, patch.length);
        ShieldChunkStore.writeAll(target, KEY, second);
        assertArrayEquals(second, readAll(target));
        assertTrue(ShieldChunkStore.matches(target));
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
