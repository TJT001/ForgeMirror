package dev.forgemirror.shield;

import android.content.Context;
import android.util.Log;

import dev.forgemirror.shield.yidun.YidunSignatures;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * PKR1 rule package loader and prototype scanner. Rules use all/any string
 * conditions; the full YARA engine can replace the matcher without changing
 * the package envelope.
 */
final class ShieldRules {
    private static final byte[] MAGIC = {'P', 'K', 'R', '1'};
    private static final int HEADER_SIZE = 26;
    private static final int TAG_SIZE = 16;
    private static final int SIGNATURE_SIZE = 64;
    private static final long MAX_SCAN_BYTES = 64L << 20;
    private static final String TAG = "ShieldRules";

    private final List<Rule> rules;
    private final ShieldYara yara;
    private final YidunSignatures yidun;
    final int version;

    private ShieldRules(List<Rule> rules, ShieldYara yara, int version,
                        YidunSignatures yidun) {
        this.rules = rules;
        this.yara = yara;
        this.version = version;
        this.yidun = yidun;
    }

    YidunSignatures yidunSignatures() {
        return yidun;
    }

    static ShieldRules load(Context context, ShieldConfig config, byte[] buildId) {
        if (config.rules == null || config.rules.isEmpty()) {
            return null;
        }
        File remote = new File(context.getFilesDir(), "shield/rules.remote.pkr");
        if (remote.isFile()) {
            try {
                byte[] pkg = readFile(remote);
                ShieldRules loaded = parsePackage(context, config, buildId, pkg);
                Log.i(TAG, "loaded remote rules version=" + loaded.version);
                return loaded;
            } catch (Exception error) {
                Log.w(TAG, "remote rules rejected: " + error);
            }
        }
        try {
            byte[] pkg = ShieldAssets.read(context, config.rules);
            return parsePackage(context, config, buildId, pkg);
        } catch (Exception error) {
            Log.w(TAG, "rules unavailable: " + error);
            return null;
        }
    }

    static ShieldRules parsePackage(Context context, ShieldConfig config,
                                    byte[] buildId, byte[] pkg) throws Exception {
        {
            if (pkg == null) {
                throw new SecurityException("empty rule package");
            }
            if (pkg.length < HEADER_SIZE + TAG_SIZE + SIGNATURE_SIZE
                    || pkg[0] != MAGIC[0] || pkg[1] != MAGIC[1]
                    || pkg[2] != MAGIC[2] || pkg[3] != MAGIC[3]) {
                throw new SecurityException("bad rule package header");
            }
            ByteBuffer header = ByteBuffer.wrap(pkg, 0, HEADER_SIZE)
                    .order(ByteOrder.LITTLE_ENDIAN);
            int version = Short.toUnsignedInt(header.getShort(4));
            int cipher = header.get(8) & 0xff;
            int sigAlg = header.get(9) & 0xff;
            int plaintextLen = header.getInt(22);
            if (version != 1 || cipher != 1) {
                throw new SecurityException("unsupported rule package");
            }
            if (pkg.length != HEADER_SIZE + plaintextLen + TAG_SIZE + SIGNATURE_SIZE) {
                throw new SecurityException("rule package length mismatch");
            }
            byte[] signature = Arrays.copyOfRange(
                    pkg, pkg.length - SIGNATURE_SIZE, pkg.length);
            byte[] body = Arrays.copyOfRange(pkg, 0, pkg.length - SIGNATURE_SIZE);
            ShieldSignature.verify(context, config, sigAlg, signature, body);

            byte[] plaintext = ShieldKeyVault.decryptPackage(
                    ShieldKeyVault.DERIVE_RULES, buildId, pkg,
                    HEADER_SIZE, 10, SIGNATURE_SIZE);
            JSONObject json = new JSONObject(
                    new String(plaintext, StandardCharsets.UTF_8));
            if (!"forgemirror.rules/1".equals(json.optString("schema"))) {
                throw new SecurityException("unsupported rules schema");
            }
            YidunSignatures yidun = null;
            JSONObject yidunJson = json.optJSONObject("yidun");
            if (yidunJson != null) {
                yidun = YidunSignatures.parse(yidunJson);
                Log.i(TAG, "yidun signatures vendor=" + yidun.vendor
                        + " sample=" + yidun.sampleSha256
                        + " captured=" + yidun.captured);
            }
            List<Rule> rules = new ArrayList<>();
            JSONArray items = json.getJSONArray("rules");
            for (int index = 0; index < items.length(); index++) {
                JSONObject item = items.getJSONObject(index);
                boolean all = "all".equals(item.getString("logic"));
                JSONArray strings = item.getJSONArray("strings");
                List<byte[]> needles = new ArrayList<>();
                for (int s = 0; s < strings.length(); s++) {
                    needles.add(strings.getString(s).getBytes(StandardCharsets.UTF_8));
                }
                rules.add(new Rule(item.getString("id"), all, needles));
            }
            int ruleVersion = json.optInt("version", 1);
            Log.i(TAG, "loaded " + rules.size() + " rules version=" + ruleVersion);
            ShieldYara yara = null;
            String yaraSource = json.optString("yara", "");
            if (!yaraSource.isEmpty()) {
                try {
                    yara = new ShieldYara(yaraSource);
                    Log.i(TAG, "YARA rules compiled");
                } catch (Throwable error) {
                    Log.w(TAG, "YARA unavailable: " + error);
                }
            }
            return new ShieldRules(rules, yara, ruleVersion, yidun);
        }
    }

    static int currentVersion(Context context, ShieldConfig config) {
        File versionFile = new File(context.getFilesDir(), "shield/rules.version");
        if (versionFile.isFile()) {
            try {
                String text = new String(readFile(versionFile), StandardCharsets.UTF_8).trim();
                return Integer.parseInt(text);
            } catch (Exception ignored) {
                // Fall back to the build version.
            }
        }
        return config.rulesVersion;
    }

    private static byte[] readFile(File file) throws Exception {
        byte[] data = new byte[(int) file.length()];
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            int offset = 0;
            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);
                if (read < 0) {
                    break;
                }
                offset += read;
            }
        }
        return data;
    }

    void close() {
        if (yara != null) {
            yara.close();
        }
    }

    static final class Match {
        final String ruleId;
        final String entry;
        final String sha256;

        Match(String ruleId, String entry, String sha256) {
            this.ruleId = ruleId;
            this.entry = entry;
            this.sha256 = sha256;
        }
    }

    List<Match> scanApk(String apkPath) {
        List<Match> matches = new ArrayList<>();
        long budget = MAX_SCAN_BYTES;
        try (ZipFile archive = new ZipFile(apkPath)) {
            for (ZipEntry entry : java.util.Collections.list(archive.entries())) {
                if (entry.isDirectory() || !entry.getName().startsWith("lib/")
                        || !entry.getName().endsWith(".so")) {
                    continue;
                }
                String entryName = entry.getName();
                if (entryName.contains("/libshield") || entryName.contains("/libshadowhook")) {
                    continue;
                }
                byte[] data = read(archive.getInputStream(entry),
                        Math.min(entry.getSize(), budget));
                budget -= data.length;
                if (yara != null) {
                    for (String id : yara.scan(data)) {
                        matches.add(new Match(id, entry.getName(), sha256(data)));
                        Log.w(TAG, "yara matched: " + id + " in " + entry.getName());
                    }
                } else {
                    for (Rule rule : rules) {
                        if (rule.matches(data)) {
                            matches.add(new Match(rule.id, entry.getName(), sha256(data)));
                            Log.w(TAG, "rule matched: " + rule.id + " in " + entry.getName());
                        }
                    }
                }
                if (budget <= 0) {
                    break;
                }
            }
        } catch (Exception error) {
            Log.w(TAG, "scan failed: " + error);
        }
        return matches;
    }

    private static String sha256(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                builder.append(String.format(Locale.US, "%02x", item & 0xff));
            }
            return builder.toString();
        } catch (Exception error) {
            return "";
        }
    }

    static byte[] read(InputStream stream, long limit) throws Exception {
        try (InputStream input = stream) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            long remaining = limit <= 0 ? Long.MAX_VALUE : limit;
            int read;
            while (remaining > 0 && (read = input.read(chunk, 0,
                    (int) Math.min(chunk.length, remaining))) != -1) {
                output.write(chunk, 0, read);
                remaining -= read;
            }
            return output.toByteArray();
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return false;
        }
        outer:
        for (int index = 0; index <= haystack.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static final class Rule {
        final String id;
        final boolean all;
        final List<byte[]> needles;

        Rule(String id, boolean all, List<byte[]> needles) {
            this.id = id;
            this.all = all;
            this.needles = needles;
        }

        boolean matches(byte[] data) {
            if (all) {
                for (byte[] needle : needles) {
                    if (!contains(data, needle)) {
                        return false;
                    }
                }
                return true;
            }
            for (byte[] needle : needles) {
                if (contains(data, needle)) {
                    return true;
                }
            }
            return false;
        }
    }
}
