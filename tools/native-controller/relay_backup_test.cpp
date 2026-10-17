#include "relay_backup.h"
#include "relay_vault.h"
#include <fstream>
#include <cstdio>
#include <algorithm>

static void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> static void rejects(F action) {
    bool rejected = false; try { action(); } catch (...) { rejected = true; }
    need(rejected, "invalid backup/restore accepted");
}
static Bytes read(const std::filesystem::path &p) {
    std::ifstream f(p, std::ios::binary); return Bytes((std::istreambuf_iterator<char>(f)), {});
}
static void write(const std::filesystem::path &p, const Bytes &b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char *>(b.data()), b.size());
    f.flush(); need(f.good(), "test fixture write failed");
}
int main() {
    auto nonce = randomBytes(12);
    const auto dir = std::filesystem::temp_directory_path() / ("pf2-backup-test-" + hex(nonce.data(), nonce.size()));
    const auto path = dir / "vault.dpapi", archive = dir / "backup.pf2bak", restored = dir / "restored.dpapi";
    const std::wstring password = L"separate-test-password-中文";
    try {
        relay::Vault::create(path); Bytes saved; const auto originalMarker = read(path.wstring() + L".lock");
        {
            relay::Vault vault(path); const auto original = read(path); const auto revision = vault.revision();
            for (const auto &bad : {std::wstring(11, L'a'), std::wstring(257, L'a'), std::wstring(1, wchar_t(0xd800)), std::wstring(L"123456789012\0x", 14)})
                rejects([&] { vault.exportBackup(archive, bad); });
            need(!std::filesystem::exists(archive) && vault.healthy(), "invalid password mutated storage");
            rejects([&] { vault.exportBackup(path, password); });
            vault.exportBackup(archive, password); saved = read(archive);
            need(read(path) == original && vault.revision() == revision, "export mutated original");
            rejects([&] { vault.exportBackup(archive, password); }); need(read(archive) == saved, "backup overwritten");
            const auto second = dir / "second.pf2bak"; vault.exportBackup(second, password);
            need(read(second) != saved, "backup salt and nonce reused");
            const auto invalid = dir / "invalid.pf2bak";
            for (auto index : {size_t(0), size_t(8), size_t(12), size_t(44), size_t(56), size_t(60), saved.size() - 1}) {
                auto changed = saved; changed[index] ^= 1; write(invalid, changed);
                rejects([&] { relay::Vault::restoreBackup(invalid, password, restored); });
                need(!std::filesystem::exists(restored) && !std::filesystem::exists(restored.wstring() + L".lock"), "bad archive created marker");
            }
            rejects([&] { relay::Vault::restoreBackup(archive, L"wrong-test-password", restored); });
            rejects([&] { relay::Vault::restoreBackup(archive, password, path); });
            need(read(path) == original, "restore replaced occupied vault");
            relay::Vault::restoreBackup(archive, password, restored);
            { relay::Vault recovered(restored); need(recovered.revision() == revision && recovered.accounts().empty(), "restore lost identity/version"); }
            need(read(restored.wstring() + L".lock") == originalMarker, "restore changed identity");
            rejects([&] { relay::Vault::restoreBackup(archive, password, restored); });
            // Missing initialized data must never be silently recreated, even by import.
            std::filesystem::remove(restored);
            rejects([&] { relay::Vault::restoreBackup(archive, password, restored); });
            need(!std::filesystem::exists(restored), "import erased initialization history");
            rejects([&] { vault.exportBackup(dir / "missing-parent" / "backup.pf2bak", password); });
            need(vault.healthy() && read(path) == original, "backup destination failure damaged source");
            // An external write while the OS lock is held must stop the exporter.
            auto changed = original; changed.back() ^= 1; write(path, changed);
            rejects([&] { vault.exportBackup(dir / "stale.pf2bak", password); });
            need(!vault.healthy() && !std::filesystem::exists(dir / "stale.pf2bak"), "stale state exported");
            rejects([&] { vault.accounts(); });
        }
        std::filesystem::remove_all(dir);
        // Cloud recovery codes: generated, 26 Crockford base32 characters, forgiving input.
        auto code = relay::backup::newRecoveryCode(), second = relay::backup::newRecoveryCode();
        need(code.size() == 26 && code != second && std::all_of(code.begin(), code.end(), [](wchar_t c) {
            return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z' && c != L'I' && c != L'L' && c != L'O' && c != L'U'); }), "recovery code alphabet");
        auto shown = relay::backup::displayRecoveryCode(code);
        need(shown.size() == 30 && shown[5] == L'-' && shown[23] == L'-' && relay::backup::recoveryCode(shown) == code, "recovery code display roundtrip");
        std::wstring lower; for (auto c : shown) lower.push_back(c >= L'A' && c <= L'Z' ? static_cast<wchar_t>(c - L'A' + L'a') : c == L'-' ? L' ' : c);
        need(relay::backup::recoveryCode(lower) == code, "recovery code case/spaces");
        need(relay::backup::recoveryCode(L"OIL0000000000000000000000Z") == L"0110000000000000000000000Z", "recovery code ambiguous letters");
        rejects([] { relay::backup::recoveryCode(L"0000000000000000000000000"); });
        rejects([] { relay::backup::recoveryCode(L"000000000000000000000000000"); });
        rejects([] { relay::backup::recoveryCode(L"U000000000000000000000000Z"); });
        auto sealed = relay::backup::encrypt(Bytes(40, 7), code);
        need(relay::backup::decrypt(sealed, relay::backup::recoveryCode(lower)) == Bytes(40, 7), "recovery code as cloud vault key");
        rejects([&] { relay::backup::decrypt(sealed, second); });
        puts("PASS: recovery codes, portable backup authentication, randomness, no-overwrite restore, marker preservation and stale-vault rejection");
        return 0;
    } catch (const std::exception &e) {
        fprintf(stderr, "FAIL: %s\n", e.what()); std::filesystem::remove_all(dir); return 1;
    }
}
