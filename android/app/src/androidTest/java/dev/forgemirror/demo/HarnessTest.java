package dev.forgemirror.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.database.Cursor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

@RunWith(AndroidJUnit4.class)
public class HarnessTest {
    @Test
    public void storageAndProviderWork() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        HarnessStorage.exercise(context);
        assertTrue(new File(context.getFilesDir(), "harness.txt").exists());

        try (Cursor cursor = context.getContentResolver().query(
                HarnessProvider.CONTENT_URI, null, null, null, null)) {
            assertNotNull(cursor);
            assertEquals(1, cursor.getCount());
        }
    }
}
