package dev.forgemirror.shield;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.util.Log;

public final class ShieldAppComponentFactory extends AppComponentFactory {
    private static final String TAG = "ShieldComponentFactory";

    private AppComponentFactory delegate;

    private AppComponentFactory delegate(ClassLoader loader) {
        if (delegate != null) {
            return delegate;
        }
        ShieldConfig config = ShieldRuntime.getConfig();
        if (config == null || config.originalFactory.isEmpty()
                || config.originalFactory.equals(getClass().getName())) {
            return null;
        }
        try {
            Class<?> type = Class.forName(config.originalFactory, true, loader);
            delegate = (AppComponentFactory) type.getDeclaredConstructor().newInstance();
            Log.i(TAG, "delegating to " + config.originalFactory);
        } catch (Throwable error) {
            Log.w(TAG, "original factory unavailable: " + config.originalFactory, error);
            delegate = null;
        }
        return delegate;
    }

    private static boolean isShieldClass(String className) {
        return className != null && className.startsWith("dev.forgemirror.shield.");
    }

    private static ClassLoader loaderFor(ClassLoader fallback) {
        ClassLoader memory = ShieldRuntime.getClassLoader();
        return memory != null ? memory : fallback;
    }

    private static <T> T instantiate(ClassLoader loader, String className, Class<T> base)
            throws Exception {
        Class<?> type = Class.forName(className, true, loader);
        return base.cast(type.getDeclaredConstructor().newInstance());
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldApplication.class.getName().equals(className)) {
            return new ShieldApplication();
        }
        ClassLoader loader = loaderFor(cl);
        AppComponentFactory factory = delegate(loader);
        if (factory != null) {
            try {
                return factory.instantiateApplication(loader, className);
            } catch (Throwable error) {
                Log.w(TAG, "delegate application failed: " + className, error);
            }
        }
        if (ShieldRuntime.getClassLoader() != null) {
            try {
                return instantiate(loader, className, Application.class);
            } catch (Throwable error) {
                Log.w(TAG, "memory application failed: " + className, error);
            }
        }
        return super.instantiateApplication(cl, className);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced provider: " + className);
            return new ShieldStubProvider();
        }
        if (isShieldClass(className)) {
            return super.instantiateProvider(cl, className);
        }
        ClassLoader loader = loaderFor(cl);
        AppComponentFactory factory = delegate(loader);
        if (factory != null) {
            try {
                return factory.instantiateProvider(loader, className);
            } catch (Throwable error) {
                Log.w(TAG, "delegate provider failed: " + className, error);
            }
        }
        if (ShieldRuntime.getClassLoader() != null) {
            try {
                return instantiate(loader, className, ContentProvider.class);
            } catch (Throwable error) {
                Log.w(TAG, "memory provider failed: " + className, error);
            }
        }
        return super.instantiateProvider(cl, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced activity: " + className);
            return new ShieldRecoveryActivity();
        }
        if (isShieldClass(className)) {
            return super.instantiateActivity(cl, className, intent);
        }
        ClassLoader loader = loaderFor(cl);
        AppComponentFactory factory = delegate(loader);
        if (factory != null) {
            try {
                return factory.instantiateActivity(loader, className, intent);
            } catch (Throwable error) {
                Log.w(TAG, "delegate activity failed: " + className, error);
            }
        }
        if (ShieldRuntime.getClassLoader() != null) {
            try {
                return instantiate(loader, className, Activity.class);
            } catch (Throwable error) {
                Log.w(TAG, "memory activity failed: " + className, error);
            }
        }
        return super.instantiateActivity(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced service: " + className);
            return new ShieldStubService();
        }
        if (isShieldClass(className)) {
            return super.instantiateService(cl, className, intent);
        }
        ClassLoader loader = loaderFor(cl);
        AppComponentFactory factory = delegate(loader);
        if (factory != null) {
            try {
                return factory.instantiateService(loader, className, intent);
            } catch (Throwable error) {
                Log.w(TAG, "delegate service failed: " + className, error);
            }
        }
        if (ShieldRuntime.getClassLoader() != null) {
            try {
                return instantiate(loader, className, Service.class);
            } catch (Throwable error) {
                Log.w(TAG, "memory service failed: " + className, error);
            }
        }
        return super.instantiateService(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced receiver: " + className);
            return new ShieldStubReceiver();
        }
        if (isShieldClass(className)) {
            return super.instantiateReceiver(cl, className, intent);
        }
        ClassLoader loader = loaderFor(cl);
        AppComponentFactory factory = delegate(loader);
        if (factory != null) {
            try {
                return factory.instantiateReceiver(loader, className, intent);
            } catch (Throwable error) {
                Log.w(TAG, "delegate receiver failed: " + className, error);
            }
        }
        if (ShieldRuntime.getClassLoader() != null) {
            try {
                return instantiate(loader, className, BroadcastReceiver.class);
            } catch (Throwable error) {
                Log.w(TAG, "memory receiver failed: " + className, error);
            }
        }
        return super.instantiateReceiver(cl, className, intent);
    }
}
