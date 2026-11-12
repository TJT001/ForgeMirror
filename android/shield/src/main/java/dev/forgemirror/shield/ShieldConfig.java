package dev.forgemirror.shield;

import android.content.Context;

import org.json.JSONObject;

final class ShieldConfig {
    final String originalApplication;
    final String originalFactory;
    final String shellVersion;
    final String container;
    final String manifest;
    final String trustedKey;

    private ShieldConfig(
            String originalApplication,
            String originalFactory,
            String shellVersion,
            String container,
            String manifest,
            String trustedKey) {
        this.originalApplication = originalApplication;
        this.originalFactory = originalFactory;
        this.shellVersion = shellVersion;
        this.container = container;
        this.manifest = manifest;
        this.trustedKey = trustedKey;
    }

    static ShieldConfig load(Context context) throws Exception {
        JSONObject json = ShieldAssets.readJson(context, "shield/config.json");
        return new ShieldConfig(
                json.optString("original_application", ""),
                json.optString("original_factory", ""),
                json.optString("shell_version", ""),
                json.optString("container", "assets/container.fdx"),
                json.optString("manifest", "shield/manifest.sig"),
                json.optString("trusted_key", "shield/trusted_key.der"));
    }
}
