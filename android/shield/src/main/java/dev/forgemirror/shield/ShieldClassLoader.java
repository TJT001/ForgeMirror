package dev.forgemirror.shield;

import android.content.Context;
import android.os.Build;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipFile;

import dalvik.system.BaseDexClassLoader;

/**
 * Class loader for container DEX. Extends BaseDexClassLoader (InMemoryDexClassLoader
 * is final and cannot override findLibrary) and assembles in-memory dex elements via
 * the public DexPathList.makeInMemoryDexElements. findLibrary maps business
 * System.loadLibrary calls to libs packaged inside the host APK, which is what the
 * stock InMemoryDexClassLoader cannot resolve.
 */
final class ShieldClassLoader extends BaseDexClassLoader {
    private final Context context;
    private final String apkPath;
    private final String[] abis;

    ShieldClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent, Context context) {
        super("", null, null, parent);
        this.context = context;
        this.apkPath = context.getApplicationInfo().sourceDir;
        this.abis = Build.SUPPORTED_ABIS;
        installDexElements(dexBuffers);
    }

    private void installDexElements(ByteBuffer[] dexBuffers) {
        try {
            Method make = Class.forName("dalvik.system.DexPathList")
                    .getDeclaredMethod("makeInMemoryDexElements",
                            ByteBuffer[].class, List.class);
            make.setAccessible(true);
            List<IOException> suppressed = new ArrayList<>();
            Object elements = make.invoke(null, dexBuffers, suppressed);
            if (!suppressed.isEmpty()) {
                throw new IllegalStateException("dex element failures: " + suppressed);
            }
            Field pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(this);
            Field elementsField = pathList.getClass().getDeclaredField("dexElements");
            elementsField.setAccessible(true);
            elementsField.set(pathList, elements);
        } catch (Exception error) {
            throw new IllegalStateException("in-memory dex install failed", error);
        }
    }

    @Override
    public String findLibrary(String libName) {
        String mapped = System.mapLibraryName(libName);
        String memory = ShieldNativeLoader.findLibrary(context, apkPath, abis,
                mapped, ShieldRuntime.nativeKey(), this);
        if (memory != null) {
            return memory;
        }
        try (ZipFile apk = new ZipFile(apkPath)) {
            for (String abi : abis) {
                if (apk.getEntry("lib/" + abi + "/" + mapped) != null) {
                    return apkPath + "!/lib/" + abi + "/" + mapped;
                }
            }
        } catch (IOException ignored) {
            // Fall through to the default resolution below.
        }
        return super.findLibrary(libName);
    }
}
