package dev.forgemirror.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import dev.forgemirror.shield.ShieldRuntime;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class ShieldRuntimeTest {
    @Test public void bootstrapLinksCoreThroughCAbi() {
        assertEquals(1, ShieldRuntime.abiVersion());
        assertTrue(ShieldRuntime.describe().contains("Core ABI v1 ready"));
    }
}
