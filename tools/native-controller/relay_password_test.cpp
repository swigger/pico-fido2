#include "relay_password.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static unsigned char nextByte = 0;
extern "C" {
bool remote_presence_derive_key(const char *purpose, uint8_t key[32]) {
    if (!purpose || strcmp(purpose, "pico-fido2 relay password key v1")) return false;
    memset(key, 0x5a, 32);
    return true;
}
void picok_random_fill(void *buffer, size_t length) {
    auto *p = static_cast<unsigned char *>(buffer);
    for (size_t i = 0; i < length; ++i) p[i] = ++nextByte;
}
}
static relay_config_t one(const char *password, size_t length) {
    relay_config_t c{};
    c.mode = RELAY_MODE_RELAY;
    c.network_count = 1;
    auto &n = c.networks[0];
    n.ssid_length = 3; memcpy(n.ssid, "net", 3);
    n.password_length = static_cast<uint8_t>(length); memcpy(n.password, password, length);
    n.host_length = 11; memcpy(n.host, "key.example", 11);
    n.port = 443;
    return c;
}
int main() {
    try {
        const uint8_t serial[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        const uint8_t other[16] = {'f','e','d','c','b','a','9','8','7','6','5','4','3','2','1','0'};
        const std::string password = "test-only-wifi-password";
        char token[RELAY_MAX_PASSWORD]; size_t tokenLength = 0;
        check(relay_password_seal(serial, password.data(), password.size(), token, sizeof(token), &tokenLength),
              "seal failed");
        check(relay_config_password_token(token, tokenLength), "token shape");
        check(std::search(token, token + tokenLength, password.begin(), password.end()) == token + tokenLength,
              "token contains plaintext");
        char opened[RELAY_MAX_PASSWORD_PLAIN]; size_t openedLength = 0;
        check(relay_password_open(serial, token, tokenLength, opened, sizeof(opened), &openedLength) &&
              openedLength == password.size() && !memcmp(opened, password.data(), password.size()), "open failed");
        check(!relay_password_open(other, token, tokenLength, opened, sizeof(opened), &openedLength),
              "token opened on another device");
        auto tampered = std::string(token, tokenLength);
        tampered[20] = tampered[20] == '0' ? '1' : '0';
        check(!relay_password_open(serial, tampered.data(), tampered.size(), opened, sizeof(opened), &openedLength),
              "tampered token opened");
        check(!relay_password_open(serial, token, tokenLength - 1, opened, sizeof(opened), &openedLength),
              "truncated token opened");
        char small[8]; size_t smallLength = 0;
        check(!relay_password_open(serial, token, tokenLength, small, sizeof(small), &smallLength),
              "small output accepted");

        auto config = one(token, tokenLength);
        check(relay_password_config_valid(&config, serial), "token config rejected");
        check(!relay_password_config_valid(&config, other), "foreign token config accepted");
        check(relay_password_resolve_config(&config, serial) &&
              config.networks[0].password_length == password.size() &&
              !memcmp(config.networks[0].password, password.data(), password.size()), "resolve failed");
        relay_config_clear(&config);

        config = one(password.data(), password.size());
        check(relay_password_config_valid(&config, serial), "plaintext config rejected");
        check(relay_password_resolve_config(&config, serial), "plaintext resolve failed");
        relay_config_clear(&config);

        char bad[RELAY_MAX_PASSWORD]; memset(bad, 'x', sizeof(bad));
        check(!relay_config_password_token(bad, 8), "bad token shape");
        check(relay_config_password_plain("12345678", 8), "short plaintext");
        check(relay_config_password_plain("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64),
              "raw PSK");
        check(!relay_config_password_plain("z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64),
              "non-hex raw PSK");
        check(!relay_config_password_plain("1234567", 7), "too short plaintext");
        check(relay_config_password_plain("123456789", 9), "ordinary plaintext");

        std::string maximum(64, 'a');
        check(relay_password_seal(serial, maximum.data(), maximum.size(), token, sizeof(token), &tokenLength) &&
              tokenLength == RELAY_PASSWORD_TOKEN_MAX_LENGTH, "maximum token length");
        check(relay_password_open(serial, token, tokenLength, opened, sizeof(opened), &openedLength) &&
              openedLength == maximum.size() && !memcmp(opened, maximum.data(), maximum.size()), "maximum open");
        puts("PASS: device-sealed Wi-Fi password tokens, binding, tamper rejection and plaintext compatibility");
        return 0;
    } catch (const std::exception &e) {
        fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
