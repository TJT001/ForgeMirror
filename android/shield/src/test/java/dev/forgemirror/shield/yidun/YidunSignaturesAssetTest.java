package dev.forgemirror.shield.yidun;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class YidunSignaturesAssetTest {
    @Test
    public void assetCarriesProvenance() throws IOException {
        File asset = new File("src/main/assets/yidun-signatures.json");
        assertTrue("signature asset missing", asset.isFile());
        String json = new String(Files.readAllBytes(asset.toPath()), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"schema\": \"forgemirror.yidun-signatures/1\""));
        assertTrue(json.contains("\"vendor\": \"NetEase Yidun\""));
        assertTrue(json.contains("\"captured\""));
        assertTrue(json.contains(
                "8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff"));
        assertTrue(json.contains("\"su_paths\""));
        assertTrue(json.contains("\"cloud_phone_prefixes\""));
        assertTrue(json.contains("\"cloud_services\""));
        assertTrue(json.contains("\"standard_magic\""));
        assertTrue(json.contains("\"dex2oat_markers\""));
        assertFalse(json.contains("\"rom_context\""));
    }
}
