#include "core.h"
#include "test_process.h"
#include <cstdio>
#include <cstring>

namespace {
constexpr const char *purpose = "synthetic protection fixture";
const Bytes plain{1, 2, 3, 4};
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> void rejects(F action) {
    bool rejected = false; try { action(); } catch (...) { rejected = true; }
    need(rejected, "invalid protection envelope accepted");
}
}
int main(int argc, char **argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--read-fixture") {
            auto path = std::filesystem::u8path(argv[2]);
            need(path.parent_path().filename().u8string().rfind("pf2-protection-test-", 0) == 0, "not a test fixture");
            need(platform::unprotect(platform::readFile(path, 4096, "cannot read fixture"), purpose) == plain,
                 "child could not decrypt test fixture");
            return 0;
        }
        need(argc == 1, "unexpected test arguments");
        selfTest(); // Same crypto checks as the CLI, using synthetic local protection.
        auto sealed = platform::protect(plain, purpose);
        need(sealed.size() == plain.size() + 36 && !std::memcmp(sealed.data(), "PF2TEST1", 8), "test used production protection");
        need(platform::unprotect(sealed, purpose) == plain, "test protection roundtrip failed");
        need(platform::protect(plain, purpose) != sealed, "test nonces were reused");
        rejects([&] { (void)platform::unprotect(sealed, "wrong purpose"); });
        auto damaged = sealed; damaged.back() ^= 1;
        rejects([&] { (void)platform::unprotect(damaged, purpose); });
        auto production = sealed; std::memcpy(production.data(), "PF2SEAL1", 8);
        rejects([&] { (void)platform::unprotect(production, purpose); });
        auto nonce = randomBytes(12);
        auto dir = std::filesystem::temp_directory_path() / ("pf2-protection-test-" + hex(nonce.data(), nonce.size()));
        platform::createPrivateDirectories(dir);
        struct Cleanup { std::filesystem::path p; ~Cleanup() { std::error_code error; std::filesystem::remove_all(p, error); } } cleanup{dir};
        auto file = dir / "fixture"; platform::writeNewFile(file, sealed, "cannot write fixture");
        need(test::run(platform::executablePath(), {"--read-fixture", file.u8string()}, 5000) == 0, "test child failed");
        std::puts("PASS: crypto, isolated test protection, tampering rejection and subprocess roundtrip (no OS keyring)");
    } catch (const std::exception &error) { std::fprintf(stderr, "FAIL: %s\n", error.what()); return 1; }
    return 0;
}
