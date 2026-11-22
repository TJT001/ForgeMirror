// Host-side test for the native white-box vault and FDX2 reader.
#include "fm_vault.h"
#include "fm_whitebox.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> read_file(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                                std::istreambuf_iterator<char>());
}

bool equal(const uint8_t *data, const std::vector<uint8_t> &expected) {
    return std::memcmp(data, expected.data(), expected.size()) == 0;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        std::cerr << "usage: vault_test <vector-dir> [generated-dir]\n";
        return 2;
    }
    fs::path dir = argv[1];
    try {
        auto table = read_file(dir / "wbaes.flat");
        auto blob = read_file(dir / "key.wb");
        auto container = read_file(dir / "container.fdx");
        auto build_id = read_file(dir / "build_id.bin");

        fm_wb_table parsed{};
        if (fm_wb_parse(table.data(), table.size(), &parsed) != 0) {
            std::cerr << "flat table rejected\n";
            return 1;
        }
        if (fm_vault_install(blob.data(), blob.size(),
                             table.data(), table.size()) != 0) {
            std::cerr << "wrapped key install failed\n";
            return 1;
        }
        for (int id = 1; id <= 5; id++) {
            uint8_t key[32];
            if (fm_vault_derive(id, build_id.data(), key) != 0) {
                std::cerr << "derive " << id << " failed\n";
                return 1;
            }
            auto expected = read_file(dir / ("derive-" + std::to_string(id) + ".bin"));
            if (!equal(key, expected)) {
                std::cerr << "derive " << id << " mismatch\n";
                return 1;
            }
        }

        fm_file *files = nullptr;
        int count = 0;
        if (fm_container_open(container.data(), container.size(), &files, &count) != 0) {
            std::cerr << "container open failed\n";
            return 1;
        }
        if (count < 2) {
            std::cerr << "unexpected file count " << count << "\n";
            fm_container_free(files, count);
            return 1;
        }
        for (int i = 0; i < count; i++) {
            auto expected = read_file(dir / ("expected-" + std::to_string(i) + ".bin"));
            if (files[i].size != expected.size()
                || !equal(files[i].data, expected)) {
                std::cerr << "file " << i << " mismatch\n";
                fm_container_free(files, count);
                return 1;
            }
        }
        fm_container_free(files, count);

        auto tampered = container;
        tampered[tampered.size() / 2] ^= 0x40;
        if (fm_container_open(tampered.data(), tampered.size(), &files, &count) == 0) {
            std::cerr << "tampered container accepted\n";
            fm_container_free(files, count);
            return 1;
        }

        auto package = read_file(dir / "package.bin");
        auto package_plain = read_file(dir / "package-plain.bin");
        uint8_t *plain = nullptr;
        size_t plain_len = 0;
        if (fm_vault_decrypt_package(1, build_id.data(), package.data(),
                                     package.size(), 24, 8, 64,
                                     &plain, &plain_len) != 0) {
            std::cerr << "package decrypt failed\n";
            return 1;
        }
        if (plain_len != package_plain.size() || !equal(plain, package_plain)) {
            std::cerr << "package plaintext mismatch\n";
            fm_free_bytes(plain);
            return 1;
        }
        fm_free_bytes(plain);

        auto bad_package = package;
        bad_package[24 + 10] ^= 0x01;
        if (fm_vault_decrypt_package(1, build_id.data(), bad_package.data(),
                                     bad_package.size(), 24, 8, 64,
                                     &plain, &plain_len) == 0) {
            std::cerr << "tampered package accepted\n";
            fm_free_bytes(plain);
            return 1;
        }

        if (argc >= 3) {
            fs::path generated = argv[2];
            if (fs::exists(generated / "gen-table.flat")) {
                auto gen_table = read_file(generated / "gen-table.flat");
                auto gen_blob = read_file(generated / "gen-key.wb");
                auto gen_key = read_file(generated / "gen-key.bin");
                fm_wb_table gen_parsed{};
                if (fm_wb_parse(gen_table.data(), gen_table.size(), &gen_parsed) != 0) {
                    std::cerr << "generated table rejected\n";
                    return 1;
                }
                uint8_t unwrapped[32];
                if (fm_wb_unwrap(&gen_parsed, gen_blob.data(), gen_blob.size(),
                                 unwrapped) != 0) {
                    std::cerr << "generated table unwrap failed\n";
                    return 1;
                }
                if (!equal(unwrapped, gen_key)) {
                    std::cerr << "generated table key mismatch\n";
                    return 1;
                }
                auto tampered_gen = gen_blob;
                tampered_gen[16] ^= 0x01;
                uint8_t scratch[32];
                if (fm_wb_unwrap(&gen_parsed, tampered_gen.data(),
                                 tampered_gen.size(), scratch) == 0
                        && equal(scratch, gen_key)) {
                    std::cerr << "tampered generated blob produced the key\n";
                    return 1;
                }
            }
        }

        auto bad_blob = blob;
        bad_blob[16] ^= 0x01;
        if (fm_vault_install(bad_blob.data(), bad_blob.size(),
                             table.data(), table.size()) != 0) {
            std::cerr << "tampered blob rejected by layout\n";
            return 1;
        }
        uint8_t bad_key[32];
        if (fm_vault_derive(2, build_id.data(), bad_key) != 0) {
            std::cerr << "derive after tampered blob failed\n";
            return 1;
        }
        auto expected_file_key = read_file(dir / "derive-2.bin");
        if (equal(bad_key, expected_file_key)) {
            std::cerr << "tampered blob produced the original key\n";
            return 1;
        }
        fm_vault_clear();
    } catch (const std::exception &error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
    std::cout << "vault vectors ok\n";
    return 0;
}
