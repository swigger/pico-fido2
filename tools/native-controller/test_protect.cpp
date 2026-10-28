// Synthetic local protection for automated tests only. No OS keyring calls,
// environment overrides, production keys or persistent key files.
#ifndef PICO_FIDO_TEST_PROTECTION
#error "test_protect.cpp must only be compiled into ControllerTestCore"
#endif
#include "platform.h"
#include "crypto.h"
#include <cstring>

namespace platform {
namespace {
constexpr unsigned char magic[8] = {'P', 'F', '2', 'T', 'E', 'S', 'T', '1'};
// Deliberately public and stable across test executables and helper subprocesses.
// The distinct envelope prevents either adapter from accepting the other's data.
Bytes testKey() { return Bytes(32, 0xa5); }
Bytes aad(const char *purpose) {
    Bytes out(std::begin(magic), std::end(magic));
    out.insert(out.end(), purpose, purpose + std::strlen(purpose)); return out;
}
}
Bytes protect(const Bytes &plain, const char *purpose) {
    auto nonce = crypto::randomBytes(12); unsigned char tag[16];
    auto body = crypto::gcmEncrypt(testKey(), nonce.data(), aad(purpose), plain.data(), plain.size(), tag);
    Bytes out(std::begin(magic), std::end(magic));
    out.insert(out.end(), nonce.begin(), nonce.end()); out.insert(out.end(), body.begin(), body.end());
    out.insert(out.end(), tag, tag + 16); return out;
}
Bytes unprotect(const Bytes &sealed, const char *purpose) {
    constexpr const char *error = "invalid test protection envelope (real user data is not accepted)";
    if (sealed.size() < 36 || std::memcmp(sealed.data(), magic, sizeof(magic))) throw std::runtime_error(error);
    return crypto::gcmDecrypt(testKey(), sealed.data() + 8, aad(purpose), sealed.data() + 20, sealed.size() - 36,
                              sealed.data() + sealed.size() - 16, error);
}
}
