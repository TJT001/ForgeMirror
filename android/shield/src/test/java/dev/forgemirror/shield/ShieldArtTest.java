package dev.forgemirror.shield;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class ShieldArtTest {
    @Test
    public void adapterSelectionIsStable() {
        String name = ShieldArt.adapter().name();
        assertFalse(name.isEmpty());
        assertTrue(name.startsWith("art-"));
    }

    @Test
    public void emptyAdapterDoesNotRejectClasses() {
        assertTrue(ShieldArt.verifyClass(ShieldArtTest.class.getClassLoader(),
                ShieldArtTest.class.getName()));
    }

    @Test
    public void describeCarriesRuntimeFields() {
        String text = ShieldArt.describe();
        assertTrue(text.contains("sdk="));
        assertTrue(text.contains("vm="));
        assertTrue(text.contains("adapter="));
    }
}
