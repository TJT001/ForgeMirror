package dev.forgemirror.shield;

import android.content.Context;
import android.content.ContextWrapper;

/** Base context wrapper that keeps resources intact but resolves classes from memory. */
final class ShieldContextWrapper extends ContextWrapper {
    private final ClassLoader loader;

    ShieldContextWrapper(Context base, ClassLoader loader) {
        super(base);
        this.loader = loader;
    }

    @Override
    public ClassLoader getClassLoader() {
        return loader != null ? loader : super.getClassLoader();
    }
}
