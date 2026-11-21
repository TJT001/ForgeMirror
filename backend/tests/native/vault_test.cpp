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
    if (argc != 2) {
        std::cerr << "usage: vault_test <vector-dir>\n";
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
