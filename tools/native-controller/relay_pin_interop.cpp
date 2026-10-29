// Host-only stdin/stdout adapter for independent python-fido2 protocol tests.
// No USB, sockets, production paths or real approval UI. apple.com is synthetic.
#include "relay_authenticator.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <cstring>
#include "cli.h"
#include "test_process.h"

static void need(bool ok) { if (!ok) throw std::runtime_error("invalid test input"); }
static Bytes bytes(const std::string &text) {
    need(text.size() % 2 == 0 && text.size() <= 4096); Bytes out;
    auto digit = [](char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; throw std::runtime_error("invalid hex"); };
    for (size_t i = 0; i < text.size(); i += 2) out.push_back(static_cast<uint8_t>((digit(text[i]) << 4) | digit(text[i + 1]))); return out;
}
static void legacyFixture(const std::filesystem::path &path) {
    // Reconstruct the previous on-disk version from a test vault with no PINs.
    std::ifstream input(path, std::ios::binary); Bytes cipher((std::istreambuf_iterator<char>(input)), {}); input.close();
    constexpr const char *purpose = "Pico FIDO relay vault v1";
    Bytes plain = platform::unprotect(cipher, purpose);
    struct Clear { Bytes &b; ~Clear() { wipe(b); } } clear{plain};
    need(plain.size() >= 38 && !memcmp(plain.data(), "PF2VLT02", 8));
    auto u32 = [&](size_t at) { need(at + 4 <= plain.size()); uint32_t n = 0; for (unsigned i = 0; i < 4; ++i) n |= uint32_t(plain[at + i]) << (8 * i); return n; };
    auto count = u32(32); need(count <= relay::Vault::capacity); size_t pos = 36;
    for (uint32_t i = 0; i < count; ++i) { auto n = u32(pos); pos += 4; need(n <= 2048 && pos + n <= plain.size()); pos += n; }
    need(pos + 2 == plain.size() && plain[pos] == 0 && plain[pos + 1] == 0);
    plain.resize(plain.size() - 2); plain[7] = '1';
    auto encrypted = platform::protect(plain, purpose);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char *>(encrypted.data()), static_cast<std::streamsize>(encrypted.size())); output.flush(); need(output.good());
}
int main(int argc, char **argv) {
    try {
        auto args = commandLine(argc, argv);
        need(args.size() == 1 || (args.size() == 2 && (args[1] == "--legacy" || args[1] == "--restore")));
        auto path = std::filesystem::absolute(std::filesystem::u8path(args[0]));
        need(path.filename() == "pin-test.dpapi" && path.parent_path().filename().u8string().rfind("pf2-pin-interop-", 0) == 0);
        const auto archive = path.parent_path() / L"backup.pf2bak";
        const std::wstring backupPassword = L"portable-fixture-password-中文";
        if (args.size() == 2 && args[1] == "--restore") relay::Vault::restoreBackup(archive, backupPassword, path);
        if (!std::filesystem::exists(path)) relay::Vault::create(path);
        if (args.size() == 2 && args[1] == "--legacy") legacyFixture(path);
        relay::Vault vault(path); unsigned decisions = 0, mode = 0; bool canceled = false; int64_t seconds = 0;
        Bytes current; relay::Operation op; auto origin = std::chrono::steady_clock::now();
        relay::Authenticator auth(vault, [&](const relay::Approval &a, const auto &) {
            need(a.deviceSerial == op.deviceSerial && a.requestId == op.requestId && a.requestHash == hash(current));
            need(!a.batchWindowSeconds || (a.batchWindowSeconds == 15 && a.operation == 2 && a.accounts.empty()));
            need(a.rp.empty() || a.rp == "apple.com" || (a.rp.size() >= 8 && a.rp.substr(a.rp.size() - 8) == ".invalid"));
            if (a.operation == 6) need(a.accounts.empty() && a.pinSubcommand == ctap::decode(Bytes(current.begin() + 1, current.end())).at(2).number);
            if (a.pinSubcommand == 0x80) {
                need((a.operation == 1 || a.operation == 2) && a.accounts.empty());
                const auto parameter = ctap::decode(Bytes(current.begin() + 1, current.end())).at(a.operation == 1 ? 8 : 6);
                need(parameter.type == ctap::Value::ByteString && parameter.bytes.empty());
            }
            ++decisions; if (mode == 2) canceled = true;
            return relay::Decision{mode != 1, a.accounts.empty() ? Bytes{} : a.accounts.front().credentialId};
        }, [&] { return origin + std::chrono::seconds(seconds); });
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line == "CANCEL_RESPONSE") {
                auth.cancel(op);
                std::cout << "00 " << decisions << " " << vault.revision() << std::endl; continue;
            }
            if (line == "BACKUP") {
                vault.exportBackup(archive, backupPassword);
                std::cout << "00 " << decisions << " " << vault.revision() << std::endl; continue;
            }
            if (line == "RESET_PIN") {
                (void)vault.resetDevicePin(op.deviceSerial);
                std::cout << "00 " << decisions << " " << vault.revision() << std::endl; continue;
            }
            need(line.size() < 8192); std::istringstream input(line); std::string boot, enrollment, payload;
            need(bool(input >> op.deviceSerial >> boot >> enrollment >> mode >> seconds >> payload));
            auto b = bytes(boot), e = bytes(enrollment); need(b.size() == 16 && e.size() == 16 && mode <= 3 && seconds >= 0);
            std::copy(b.begin(), b.end(), op.bootId.begin()); std::copy(e.begin(), e.end(), op.enrollmentId.begin());
            auto id = randomBytes(16); std::copy(id.begin(), id.end(), op.requestId.begin());
            op.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10); canceled = false; op.canceled = [&] { return canceled; };
            current = bytes(payload);
            std::unique_ptr<test::BlockReplace> blocker;
            if (mode == 3) blocker = std::make_unique<test::BlockReplace>(path);
            auto response = auth.exchange(current, op);
            blocker.reset();
            std::cout << hex(response.data(), response.size()) << " " << decisions << " " << vault.revision() << std::endl;
        }
        return 0;
    } catch (const std::exception &e) { std::cerr << "PIN test adapter failed: " << e.what() << std::endl; return 1; }
}
