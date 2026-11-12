package dev.forgemirror.shield;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.util.Log;

public final class ShieldAppComponentFactory extends AppComponentFactory {
    private static final String TAG = "ShieldComponentFactory";

    private AppComponentFactory delegate;
    private boolean delegateResolved;

    private AppComponentFactory delegate(ClassLoader loader) {
        if (delegateResolved) {
            return delegate;
        }
        delegateResolved = true;
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

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldApplication.class.getName().equals(className)) {
            return new ShieldApplication();
        }
        AppComponentFactory factory = delegate(cl);
        return factory != null
                ? factory.instantiateApplication(cl, className)
                : super.instantiateApplication(cl, className);
    }

    @Override
    public android.content.ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced provider: " + className);
            return new ShieldStubProvider();
        }
        AppComponentFactory factory = delegate(cl);
        return factory != null
                ? factory.instantiateProvider(cl, className)
                : super.instantiateProvider(cl, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced activity: " + className);
            return new ShieldRecoveryActivity();
        }
        AppComponentFactory factory = delegate(cl);
        return factory != null
                ? factory.instantiateActivity(cl, className, intent)
                : super.instantiateActivity(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced service: " + className);
            return new ShieldStubService();
        }
        AppComponentFactory factory = delegate(cl);
        return factory != null
                ? factory.instantiateService(cl, className, intent)
                : super.instantiateService(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ShieldRuntime.isRecovery() && !isShieldClass(className)) {
            Log.w(TAG, "recovery gate replaced receiver: " + className);
            return new ShieldStubReceiver();
        }
        AppComponentFactory factory = delegate(cl);
        return factory != null
                ? factory.instantiateReceiver(cl, className, intent)
                : super.instantiateReceiver(cl, className, intent);
    }
}
