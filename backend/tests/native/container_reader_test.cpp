// Host-side FDX2 vector reader. Uses OpenSSL only as a test dependency; the
// Android runtime will use an approved crypto backend behind the same layout.

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr size_t kHeaderSize = 128;
constexpr size_t kEntrySize = 72;
constexpr size_t kTagSize = 16;
constexpr uint32_t kVersion = 2;
constexpr uint8_t kAlgAes256Gcm = 1;
constexpr uint8_t kKdfHkdfSha256 = 1;
constexpr uint32_t kChunkSize = 65536;
constexpr size_t kMaxFiles = 64;
constexpr uint32_t kMaxChunks = 1u << 15;
constexpr uint64_t kMaxFile = 1ull << 30;
constexpr uint64_t kMaxTotal = 2ull << 30;

uint16_t rd16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t rd32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t rd64(const uint8_t *p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

void wr16(uint8_t *p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

void wr32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

std::vector<uint8_t> read_file(const fs::path &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
}

bool hkdf_sha256(const std::vector<uint8_t> &ikm, const uint8_t *salt,
                 size_t salt_len, const char *info, std::vector<uint8_t> &out) {
    out.assign(32, 0);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx == nullptr) {
        return false;
    }
    size_t out_len = out.size();
    bool ok = false;
    do {
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            break;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) <= 0) {
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), static_cast<int>(ikm.size())) <= 0) {
            break;
        }
        if (EVP_PKEY_CTX_add1_hkdf_info(
                ctx, reinterpret_cast<const unsigned char *>(info),
                static_cast<int>(std::strlen(info))) <= 0) {
            break;
        }
        if (EVP_PKEY_derive(ctx, out.data(), &out_len) <= 0) {
            break;
        }
        ok = out_len == out.size();
    } while (false);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool aes_gcm_decrypt(const std::vector<uint8_t> &key, const uint8_t *nonce,
                     size_t nonce_len, const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     std::vector<uint8_t> &out) {
    if (key.size() != 32 || ciphertext_len < kTagSize) {
        return false;
    }
    const size_t body_len = ciphertext_len - kTagSize;
    out.assign(body_len + 16, 0);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    bool ok = false;
    int len = 0;
    size_t written = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(nonce_len), nullptr) != 1) {
            break;
        }
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
            break;
        }
        if (aad_len > 0 &&
            EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1) {
            break;
        }
        if (body_len > 0 &&
            EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext,
                              static_cast<int>(body_len)) != 1) {
            break;
        }
        written = static_cast<size_t>(len);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize),
                                const_cast<uint8_t *>(ciphertext + body_len)) != 1) {
            break;
        }
        if (EVP_DecryptFinal_ex(ctx, out.data() + written, &len) != 1) {
            break;
        }
        written += static_cast<size_t>(len);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return false;
    }
    out.resize(written);
    return true;
}

std::string sha256_hex(const std::vector<uint8_t> &data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    const unsigned char empty = 0;
    const unsigned char *input = data.empty() ? &empty : data.data();
    if (EVP_Digest(input, data.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1) {
        return {};
    }
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (unsigned int i = 0; i < length; ++i) {
        out.push_back(hex[digest[i] >> 4]);
        out.push_back(hex[digest[i] & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> chunk_aad(const uint8_t *build_id, uint32_t file_index,
                               uint32_t chunk_index, uint32_t plaintext_len) {
    std::vector<uint8_t> aad(40, 0);
    std::memcpy(aad.data(), "FDX2", 4);
    wr16(aad.data() + 4, kVersion);
    aad[6] = kAlgAes256Gcm;
    aad[7] = kKdfHkdfSha256;
    std::memcpy(aad.data() + 8, build_id, 16);
    wr32(aad.data() + 24, file_index);
    wr32(aad.data() + 28, chunk_index);
    wr32(aad.data() + 32, plaintext_len);
    wr32(aad.data() + 36, 0);
    return aad;
}

struct Expected {
    std::string sha256;
    uint64_t size = 0;
    std::string name;
};

struct Entry {
    uint32_t index = 0;
    uint32_t flags = 0;
    uint64_t size = 0;
    uint32_t chunk_size = 0;
    uint32_t chunk_count = 0;
    uint64_t offset = 0;
    std::array<uint8_t, 32> sha256{};
};

bool parse_expected(const fs::path &path, std::vector<Expected> &out) {
    std::ifstream stream(path);
    if (!stream) {
        return false;
    }
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream fields(line);
        Expected expected;
        if (!(fields >> expected.sha256 >> expected.size >> expected.name)) {
            return false;
        }
        out.push_back(std::move(expected));
    }
    return true;
}

bool check_case(const fs::path &dir) {
    const std::vector<uint8_t> blob = read_file(dir / "container.fdx");
    const std::vector<uint8_t> key = read_file(dir / "key.bin");
    std::vector<Expected> expected;
    if (blob.size() < kHeaderSize || key.size() != 32 ||
        !parse_expected(dir / "expected.txt", expected)) {
        std::cerr << "FAIL " << dir << ": missing or invalid inputs\n";
        return false;
    }

    const uint8_t *header = blob.data();
    if (std::memcmp(header, "FDX2", 4) != 0 || rd16(header + 4) != kVersion ||
        rd16(header + 6) != kHeaderSize || rd32(header + 8) != 0 ||
        header[12] != kAlgAes256Gcm || header[13] != kKdfHkdfSha256 ||
        rd16(header + 14) != 0 || rd32(header + 60) != 0 || rd32(header + 76) != 0) {
        std::cerr << "FAIL " << dir << ": bad header identity\n";
        return false;
    }

    const uint32_t file_count = rd32(header + 32);
    const uint32_t chunk_size = rd32(header + 36);
    const uint8_t *build_id = header + 16;
    const uint8_t *nonce_prefix = header + 40;
    const uint8_t *toc_nonce = header + 48;
    const uint64_t total_plaintext = rd64(header + 64);
    const uint32_t total_chunks = rd32(header + 72);
    const uint64_t toc_offset = rd64(header + 80);
    const uint64_t toc_size = rd64(header + 88);

    if (file_count == 0 || file_count > kMaxFiles || chunk_size != kChunkSize ||
        total_chunks > kMaxChunks || total_plaintext > kMaxTotal ||
        toc_offset < kHeaderSize || toc_offset > blob.size() ||
        toc_size != kTagSize + kEntrySize * file_count ||
        toc_offset + toc_size != blob.size() ||
        expected.size() != file_count) {
        std::cerr << "FAIL " << dir << ": invalid header limits\n";
        return false;
    }

    std::vector<uint8_t> toc_key;
    std::vector<uint8_t> chunk_key;
    if (!hkdf_sha256(key, build_id, 16, "FM/fdx2/toc/v1", toc_key) ||
        !hkdf_sha256(key, build_id, 16, "FM/fdx2/chunk/v1", chunk_key)) {
        std::cerr << "FAIL " << dir << ": HKDF failed\n";
        return false;
    }

    std::vector<uint8_t> toc_plaintext;
    if (!aes_gcm_decrypt(toc_key, toc_nonce, 12, header, kHeaderSize,
                         blob.data() + toc_offset, toc_size, toc_plaintext) ||
        toc_plaintext.size() != kEntrySize * file_count) {
        std::cerr << "FAIL " << dir << ": TOC authentication failed\n";
        return false;
    }

    std::vector<Entry> entries;
    entries.reserve(file_count);
    uint64_t expected_offset = kHeaderSize;
    uint64_t expected_plaintext = 0;
    uint64_t expected_chunks = 0;
    for (uint32_t i = 0; i < file_count; ++i) {
        const uint8_t *entry = toc_plaintext.data() + i * kEntrySize;
        Entry parsed;
        parsed.index = rd32(entry);
        parsed.flags = rd32(entry + 4);
        parsed.size = rd64(entry + 16);
        parsed.chunk_size = rd32(entry + 24);
        parsed.chunk_count = rd32(entry + 28);
        parsed.offset = rd64(entry + 32);
        std::memcpy(parsed.sha256.data(), entry + 40, 32);

        if (parsed.index != i || parsed.flags != 0 || parsed.chunk_size != kChunkSize ||
            parsed.size > kMaxFile ||
            parsed.chunk_count != (parsed.size + kChunkSize - 1) / kChunkSize ||
            parsed.offset != expected_offset || parsed.offset > toc_offset) {
            std::cerr << "FAIL " << dir << ": invalid TOC entry " << i << "\n";
            return false;
        }
        expected_offset += parsed.size + static_cast<uint64_t>(parsed.chunk_count) * kTagSize;
        if (expected_offset > toc_offset) {
            std::cerr << "FAIL " << dir << ": TOC entry exceeds data region\n";
            return false;
        }
        expected_plaintext += parsed.size;
        expected_chunks += parsed.chunk_count;
        entries.push_back(parsed);
    }
    if (expected_offset != toc_offset || expected_plaintext != total_plaintext ||
        expected_chunks != total_chunks) {
        std::cerr << "FAIL " << dir << ": header totals mismatch\n";
        return false;
    }

    uint64_t cursor = kHeaderSize;
    uint32_t global_chunk = 0;
    for (uint32_t i = 0; i < file_count; ++i) {
        const Entry &entry = entries[i];
        std::vector<uint8_t> plaintext;
        plaintext.reserve(entry.size);
        uint64_t remaining = entry.size;
        while (remaining > 0) {
            const uint32_t length = static_cast<uint32_t>(
                std::min<uint64_t>(remaining, kChunkSize));
            const std::vector<uint8_t> aad =
                chunk_aad(build_id, i, global_chunk, length);
            std::array<uint8_t, 12> nonce{};
            std::memcpy(nonce.data(), nonce_prefix, 8);
            nonce[8] = static_cast<uint8_t>(global_chunk >> 24);
            nonce[9] = static_cast<uint8_t>(global_chunk >> 16);
            nonce[10] = static_cast<uint8_t>(global_chunk >> 8);
            nonce[11] = static_cast<uint8_t>(global_chunk);
            std::vector<uint8_t> part;
            if (!aes_gcm_decrypt(chunk_key, nonce.data(), nonce.size(), aad.data(),
                                 aad.size(), blob.data() + cursor, length + kTagSize,
                                 part) ||
                part.size() != length) {
                std::cerr << "FAIL " << dir << ": chunk authentication failed\n";
                return false;
            }
            plaintext.insert(plaintext.end(), part.begin(), part.end());
            cursor += length + kTagSize;
            remaining -= length;
            ++global_chunk;
        }

        if (sha256_hex(plaintext) != expected[i].sha256 ||
            plaintext.size() != expected[i].size) {
            std::cerr << "FAIL " << dir << ": plaintext mismatch for " << expected[i].name
                      << "\n";
            return false;
        }
    }

    if (cursor != toc_offset) {
        std::cerr << "FAIL " << dir << ": chunk region length mismatch\n";
        return false;
    }

    std::cout << "PASS " << dir.filename() << " (" << file_count << " files)\n";
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    const fs::path root = argc > 1 ? argv[1] : "backend/tests/vectors/container/v2";
    if (!fs::is_directory(root)) {
        std::cerr << "vector directory not found: " << root << "\n";
        return 2;
    }

    int failures = 0;
    int cases = 0;
    for (const fs::directory_entry &entry : fs::directory_iterator(root)) {
        if (!entry.is_directory() || !fs::exists(entry.path() / "container.fdx")) {
            continue;
        }
        ++cases;
        if (!check_case(entry.path())) {
            ++failures;
        }
    }

    if (cases == 0) {
        std::cerr << "no vector cases found in " << root << "\n";
        return 2;
    }
    return failures == 0 ? 0 : 1;
}
