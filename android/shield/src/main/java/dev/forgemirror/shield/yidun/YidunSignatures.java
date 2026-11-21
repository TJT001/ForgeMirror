package dev.forgemirror.shield.yidun;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Detection signatures derived from the NetEase Yidun {@code libnesec.so}
 * research sample. Everything in this package is provenance-tagged: rule IDs
 * use the {@code yidun_} prefix and this data file records the source sample.
 *
 * <p>Signatures are versioned data, not product rules. See
 * {@code docs/设计文档.md} §17.9 and {@code docs/research/libnesec_易盾加固还原.md}.
 */
public final class YidunSignatures {
    private static final String TAG = "YidunSignatures";
    private static final String ASSET = "yidun-signatures.json";
    private static final long MAX_ASSET_BYTES = 1L << 20;

    public final String vendor;
    public final String library;
    public final String sampleSha256;
    public final String evidence;

    public final List<String> suPaths;
    public final List<String> mountMarkers;
    public final List<String> taskStatusKeys;
    public final String zombieMarker;
    public final List<String> statusMarkers;
    public final List<String> hookMapsMarkers;
    public final List<String> hookClasses;
    public final List<String> hookServices;
    public final List<String> fdMarkers;
    public final List<String> ldPreloadMarkers;
    public final List<String> emulatorPaths;
    public final List<String> emulatorBuildMarkers;
    public final List<String> emulatorProperties;
    public final List<String> cloudPhonePrefixes;
    public final List<String> cloudServices;
    public final List<String> dexStandardMagic;
    public final List<String> dex2oatMarkers;

    YidunSignatures(String vendor, String library, String sampleSha256, String evidence,
                    List<String> suPaths, List<String> mountMarkers,
                    List<String> taskStatusKeys, String zombieMarker,
                    List<String> statusMarkers, List<String> hookMapsMarkers,
                    List<String> hookClasses, List<String> hookServices,
                    List<String> fdMarkers, List<String> ldPreloadMarkers,
                    List<String> emulatorPaths, List<String> emulatorBuildMarkers,
                    List<String> emulatorProperties, List<String> cloudPhonePrefixes,
                    List<String> cloudServices, List<String> dexStandardMagic,
                    List<String> dex2oatMarkers) {
        this.vendor = vendor;
        this.library = library;
        this.sampleSha256 = sampleSha256;
        this.evidence = evidence;
        this.suPaths = immutable(suPaths);
        this.mountMarkers = immutable(mountMarkers);
        this.taskStatusKeys = immutable(taskStatusKeys);
        this.zombieMarker = zombieMarker == null ? "" : zombieMarker;
        this.statusMarkers = immutable(statusMarkers);
        this.hookMapsMarkers = immutable(hookMapsMarkers);
        this.hookClasses = immutable(hookClasses);
        this.hookServices = immutable(hookServices);
        this.fdMarkers = immutable(fdMarkers);
        this.ldPreloadMarkers = immutable(ldPreloadMarkers);
        this.emulatorPaths = immutable(emulatorPaths);
        this.emulatorBuildMarkers = immutable(emulatorBuildMarkers);
        this.emulatorProperties = immutable(emulatorProperties);
        this.cloudPhonePrefixes = immutable(cloudPhonePrefixes);
        this.cloudServices = immutable(cloudServices);
        this.dexStandardMagic = immutable(dexStandardMagic);
        this.dex2oatMarkers = immutable(dex2oatMarkers);
    }

    public static YidunSignatures load(Context context) {
        try (InputStream input = context.getAssets().open(ASSET)) {
            String json = new String(read(input, MAX_ASSET_BYTES), StandardCharsets.UTF_8);
            return parse(json);
        } catch (Throwable error) {
            Log.w(TAG, "signatures unavailable: " + error);
            return empty();
        }
    }

    public static YidunSignatures parse(String json) throws Exception {
        return parse(new JSONObject(json));
    }

    public static YidunSignatures parse(JSONObject root) throws Exception {
        if (root == null) {
            throw new SecurityException("empty yidun signatures");
        }
        if (!"forgemirror.yidun-signatures/1".equals(root.optString("schema", ""))) {
            throw new SecurityException("unsupported yidun signature schema");
        }
        JSONObject source = root.optJSONObject("source");
        if (source == null) {
            throw new SecurityException("yidun source required");
        }
        String vendor = optString(source, "vendor");
        String library = optString(source, "library");
        String sampleSha256 = optString(source, "sample_sha256");
        String evidence = optString(source, "evidence");
        if (vendor.isEmpty() || library.isEmpty() || evidence.isEmpty()
                || sampleSha256.length() != 64 || !isHex(sampleSha256)) {
            throw new SecurityException("yidun source metadata required");
        }
        JSONObject rootChecks = root.optJSONObject("root");
        JSONObject debug = root.optJSONObject("debug");
        JSONObject hook = root.optJSONObject("hook");
        JSONObject emulator = root.optJSONObject("emulator");
        JSONObject dex = root.optJSONObject("dex");
        return new YidunSignatures(
                vendor,
                library,
                sampleSha256,
                evidence,
                strings(rootChecks, "su_paths"),
                strings(rootChecks, "mount_markers"),
                strings(debug, "task_status_keys"),
                optString(debug, "zombie_marker"),
                strings(debug, "status_markers"),
                strings(hook, "maps_markers"),
                strings(hook, "classes"),
                strings(hook, "services"),
                strings(hook, "fd_markers"),
                strings(hook, "ld_preload_markers"),
                strings(emulator, "paths"),
                strings(emulator, "build_markers"),
                strings(emulator, "properties"),
                strings(emulator, "cloud_phone_prefixes"),
                strings(emulator, "cloud_services"),
                strings(dex, "standard_magic"),
                strings(dex, "dex2oat_markers"));
    }

    private static boolean isHex(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = Character.toLowerCase(value.charAt(index));
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    public static YidunSignatures empty() {
        return new YidunSignatures("", "", "", "",
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), "",
                Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList());
    }

    public boolean isEmpty() {
        return suPaths.isEmpty() && mountMarkers.isEmpty()
                && taskStatusKeys.isEmpty() && statusMarkers.isEmpty()
                && hookMapsMarkers.isEmpty() && hookClasses.isEmpty()
                && hookServices.isEmpty() && fdMarkers.isEmpty()
                && ldPreloadMarkers.isEmpty() && emulatorPaths.isEmpty()
                && emulatorBuildMarkers.isEmpty() && emulatorProperties.isEmpty()
                && cloudPhonePrefixes.isEmpty() && cloudServices.isEmpty()
                && dexStandardMagic.isEmpty() && dex2oatMarkers.isEmpty();
    }

    private static List<String> strings(JSONObject object, String key) {
        if (object == null) {
            return Collections.emptyList();
        }
        JSONArray array = object.optJSONArray(key);
        if (array == null || array.length() == 0) {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>(array.length());
        for (int index = 0; index < array.length(); index++) {
            String value = array.optString(index, "");
            if (!value.isEmpty()) {
                values.add(value);
            }
        }
        return values;
    }

    private static String optString(JSONObject object, String key) {
        return object == null ? "" : object.optString(key, "");
    }

    private static List<String> immutable(List<String> values) {
        return values == null || values.isEmpty()
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static byte[] read(InputStream input, long limit) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long remaining = limit;
        int read;
        while (remaining > 0 && (read = input.read(chunk, 0,
                (int) Math.min(chunk.length, remaining))) != -1) {
            output.write(chunk, 0, read);
            remaining -= read;
        }
        return output.toByteArray();
    }
}
