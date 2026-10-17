#include <array>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <stdexcept>
extern "C" {
#include "otp.h"
extern uint8_t _otp_key_1[32], _otp_key_2[32];
}

namespace {
struct Block {
    bool unused = true, readProtected = false, missingField = false, readError = false;
    esp_efuse_purpose_t purpose = ESP_EFUSE_KEY_PURPOSE_USER;
    std::array<uint8_t, 32> bytes{};
    unsigned reads = 0;
};
std::array<Block, 2> blocks;
const esp_efuse_desc_t descriptions[] = {{EFUSE_BLK_KEY3}, {EFUSE_BLK_KEY4}};
const esp_efuse_desc_t *fields[2][2] = {{&descriptions[0], nullptr}, {&descriptions[1], nullptr}};
void check(bool good, const char *message) { if (!good) throw std::runtime_error(message); }
size_t index(esp_efuse_block_t block) {
    check(block == EFUSE_BLK_KEY3 || block == EFUSE_BLK_KEY4, "read unrelated eFuse block"); return block == EFUSE_BLK_KEY3 ? 0 : 1;
}
void stored(unsigned i) {
    blocks[i].unused = false;
    for (size_t j = 0; j < 32; ++j) blocks[i].bytes[j] = static_cast<uint8_t>(0x20 + 32 * i + j);
}
bool zero(const uint8_t *bytes) { return std::all_of(bytes, bytes + 32, [](uint8_t b) { return b == 0; }); }
}
extern "C" bool esp_efuse_key_block_unused(esp_efuse_block_t block) { return blocks[index(block)].unused; }
extern "C" bool esp_efuse_get_key_dis_read(esp_efuse_block_t block) { return blocks[index(block)].readProtected; }
extern "C" esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t block) { return blocks[index(block)].purpose; }
extern "C" const esp_efuse_desc_t **esp_efuse_get_key(esp_efuse_block_t block) {
    size_t i = index(block); return blocks[i].missingField ? nullptr : fields[i];
}
extern "C" esp_err_t esp_efuse_read_field_blob(const esp_efuse_desc_t *field[], void *destination, size_t bits) {
    check(field && field[0] && !field[1] && bits == 256, "wrong eFuse read shape");
    auto &block = blocks[index(field[0]->block)]; ++block.reads;
    memcpy(destination, block.bytes.data(), 32); return block.readError ? ESP_FAIL : ESP_OK;
}
int main() {
    try {
        check(init_otp_files() && !otp_key_1 && !otp_key_2, "blank device did not retain no-OTP source");
        check(!blocks[0].reads && !blocks[1].reads, "blank eFuse was read as a key");
        for (unsigned mask = 1; mask < 4; ++mask) {
            blocks = {}; for (unsigned i = 0; i < 2; ++i) if (mask & (1u << i)) stored(i);
            auto before = blocks; check(init_otp_files(), "existing eFuse key was ignored with provisioning disabled");
            check((otp_key_1 != nullptr) == bool(mask & 1) && (otp_key_2 != nullptr) == bool(mask & 2), "wrong source presence");
            if (otp_key_1) check(!memcmp(otp_key_1, before[0].bytes.data(), 32), "root key changed");
            if (otp_key_2) check(!memcmp(otp_key_2, before[1].bytes.data(), 32), "device key changed");
            check(blocks[0].bytes == before[0].bytes && blocks[1].bytes == before[1].bytes, "eFuse fixture modified");
        }
        for (unsigned failedBlock = 0; failedBlock < 2; ++failedBlock) for (unsigned reason = 0; reason < 5; ++reason) {
            blocks = {}; stored(0); stored(1); auto &bad = blocks[failedBlock];
            if (reason == 0) bad.readProtected = true;
            if (reason == 1) bad.purpose = TEST_OTHER_PURPOSE;
            if (reason == 2) bad.missingField = true;
            if (reason == 3) bad.readError = true;
            if (reason == 4) bad.bytes.fill(0); // Allocated/protected empty block is not an unused one.
            check(!init_otp_files(), "invalid root silently fell back to no-OTP");
            check(!otp_key_1 && !otp_key_2 && zero(_otp_key_1) && zero(_otp_key_2), "failed initialization retained partial key material");
            if (reason < 3) check(!bad.reads, "unreadable/unrelated block was read");
        }
        blocks = {}; check(init_otp_files() && !otp_key_1 && !otp_key_2 && zero(_otp_key_1) && zero(_otp_key_2), "stale key survived a blank boot");
        puts("PASS: actual ESP OTP initialization with provisioning disabled preserves existing keys, rejects unavailable sources, wipes failures and calls no burn API"); return 0;
    } catch (const std::exception &error) { fprintf(stderr, "FAIL: %s\n", error.what()); return 1; }
}
