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
    final String key;
    final String policy;
    final String buildId;
    final String authUrl;
    final String rules;
    final String eventUrl;
    final String eventToken;
    final boolean detection;
    final String response;
    final int rulesVersion;
    final String certSha256;
    final int maxNativeFileMb;

    private ShieldConfig(
            String originalApplication,
            String originalFactory,
            String shellVersion,
            String container,
            String manifest,
            String trustedKey,
            String key,
            String policy,
            String buildId,
            String authUrl,
            String rules,
            String eventUrl,
            String eventToken,
            boolean detection,
            String response,
            int rulesVersion,
            String certSha256,
            int maxNativeFileMb) {
        this.originalApplication = originalApplication;
        this.originalFactory = originalFactory;
        this.shellVersion = shellVersion;
        this.container = container;
        this.manifest = manifest;
        this.trustedKey = trustedKey;
        this.key = key;
        this.policy = policy;
        this.buildId = buildId;
        this.authUrl = authUrl;
        this.rules = rules;
        this.eventUrl = eventUrl;
        this.eventToken = eventToken;
        this.detection = detection;
        this.response = response;
        this.rulesVersion = rulesVersion;
        this.certSha256 = certSha256;
        this.maxNativeFileMb = maxNativeFileMb;
    }

    static ShieldConfig load(Context context) throws Exception {
        JSONObject json = ShieldAssets.readJson(context, "shield/config.json");
        return new ShieldConfig(
                json.optString("original_application", ""),
                json.optString("original_factory", ""),
                json.optString("shell_version", ""),
                json.optString("container", "container.fdx"),
                json.optString("manifest", "shield/manifest.sig"),
                json.optString("trusted_key", "shield/trusted_key.der"),
                json.optString("key", ""),
                json.optString("policy", ""),
                json.optString("build_id", ""),
                json.optString("auth_url", ""),
                json.optString("rules", "shield/rules.pkr"),
                json.optString("event_url", ""),
                json.optString("event_token", ""),
                json.optBoolean("detection", true),
                json.optString("response", "toast"),
                json.optInt("rules_version", 1),
                json.optString("cert_sha256", ""),
                json.optInt("max_native_file_mb", 128));
    }
}
