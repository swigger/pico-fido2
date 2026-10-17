#include "relay_storage.h"
#include "relay_backup.h"
#include "credentials.h"
#include "test_process.h"
#include <algorithm>
#include <cstdio>

using namespace relay;
namespace {
const std::wstring password = L"fixture-backup-password-中文";
const std::string serial = "0123456789abcdef";
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> void rejects(F action) {
    bool rejected = false; try { action(); } catch (...) { rejected = true; }
    need(rejected, "unsafe local clear accepted");
}
Bytes read(const std::filesystem::path &path) { return platform::readFile(path, 9 * 1024 * 1024, "fixture read failed"); }
void write(const std::filesystem::path &path, const Bytes &data) { platform::publishFile(path, data, true, "fixture write failed"); }
void put(Bytes &out, uint64_t value, unsigned width) { while (width--) { out.push_back(static_cast<uint8_t>(value)); value >>= 8; } }
// Independent portable fixture with a real private key, a nonzero counter and
// PIN/retry state. Full plaintext equality after restore checks every field.
Bytes fixture(const std::filesystem::path &archive, const std::string &user) {
    using V = ctap::Value;
    V resident; resident.type = V::Boolean; resident.number = 1;
    auto key = Key::generate();
    auto record = ctap::encode(V::map({V::integer(1), V::blob(randomBytes(32)), V::integer(2), V::string("fixture.example"),
        V::integer(3), V::blob({1}), V::integer(4), V::string(user), V::integer(5), V::string(user),
        V::integer(6), V::blob(key->blob()), V::integer(7), V::integer(42), V::integer(8), resident}));
    Bytes plain{'P','F','2','V','L','T','0','2'}; auto id = randomBytes(16);
    plain.insert(plain.end(), id.begin(), id.end()); put(plain, 7, 8); put(plain, 1, 4); put(plain, record.size(), 4);
    plain.insert(plain.end(), record.begin(), record.end()); put(plain, 1, 2);
    plain.insert(plain.end(), serial.begin(), serial.end()); plain.insert(plain.end(), 64, 0x5a); plain.push_back(5);
    write(archive, backup::encrypt(plain, password)); return plain;
}
std::filesystem::path localPath(const std::filesystem::path &directory) { return directory / ("credentials-v1" + platform::protectedExtension()); }
void clearing(const std::filesystem::path &directory) {
    auto first = directory / "first.pf2bak", second = directory / "second.pf2bak";
    fixture(first, "Alice"); auto secondPlain = fixture(second, "Bob");
    auto local = directory / "local", path = localPath(local), marker = test::withSuffix(path, ".lock");
    auto kept = local / "unrelated-profile", saved = local / "current.pf2bak";
    Storage storage(local); storage.restoreLocal(first, password);
    write(kept, Bytes{1,2,3});
    auto backend = local / ("backend-v1" + platform::protectedExtension()); auto selection = read(backend);
    auto &vault = storage.open(); auto identity = vault.namespaceId(); auto original = read(path);
    need(vault.accounts().size() == 1 && vault.accounts()[0].counter == 42, "fixture credentials missing");
    rejects([&] { Storage competing(local); });
    rejects([&] { storage.clearLocalAfterBackup(first, L"wrong-backup-password"); });
    rejects([&] { storage.clearLocalAfterBackup(second, password); });
    rejects([&] { storage.clearLocalAfterBackup(directory / "missing.pf2bak", password); });
    auto damaged = read(first); damaged.back() ^= 1; auto bad = directory / "damaged.pf2bak"; write(bad, damaged);
    rejects([&] { storage.clearLocalAfterBackup(bad, password); });
    need(read(path) == original && vault.healthy(), "rejected backup changed the vault");
    need(vault.resetDevicePin(serial), "fixture PIN record missing");
    original = read(path); // Same vault identity, but the old snapshot no longer covers its PIN/revision state.
    rejects([&] { storage.clearLocalAfterBackup(first, password); });
    vault.exportBackup(saved, password); auto latest = backup::decrypt(read(saved), password);
    rejects([&] { storage.clearLocalAfterBackup(saved, password, [] { return true; }); });
    need(read(path) == original && vault.healthy(), "canceled verification changed the vault");
    {
        test::BlockReplace blocked(path);
        rejects([&] { storage.clearLocalAfterBackup(saved, password); });
    }
    need(read(path) == original && storage.open().namespaceId() == identity, "delete failure did not retain a usable vault");
    storage.clearLocalAfterBackup(saved, password);
    need(!std::filesystem::exists(path) && !std::filesystem::exists(marker), "clear left the restore action blocked");
    need(read(backend) == selection && read(kept) == Bytes({1,2,3}) && backup::decrypt(read(saved), password) == latest,
        "clear deleted selection, unrelated files or the backup");
    rejects([&] { storage.open(); });
    storage.restoreLocal(second, password);
    auto &other = storage.open();
    need(other.namespaceId() != identity && other.accounts()[0].userName == "Bob", "switch to another backup failed");
    auto roundtrip = directory / "second-roundtrip.pf2bak"; other.exportBackup(roundtrip, password);
    need(backup::decrypt(read(roundtrip), password) == secondPlain, "switch lost private key, PIN, counter or identity");
    storage.clearLocalAfterBackup(roundtrip, password);
    storage.restoreLocal(saved, password);
    need(storage.open().namespaceId() == identity && storage.open().accounts()[0].userName == "Alice", "switch back failed");
    auto finalBackup = directory / "final.pf2bak"; storage.open().exportBackup(finalBackup, password);
    need(backup::decrypt(read(finalBackup), password) == latest, "switch back lost vault state");
    storage.clearLocalAfterBackup(finalBackup, password);
    storage.initializeLocal(); need(storage.open().accounts().empty(), "initialize after clear failed");
}
void interrupted(const std::filesystem::path &directory) {
    auto path = localPath(directory), marker = test::withSuffix(path, ".lock");
    { Storage storage(directory); storage.initializeLocal(); }
    auto original = read(path), normal = read(marker), clearing = normal;
    const Bytes clearMagic{'P','F','2','C','L','R','0','1'};
    std::copy(clearMagic.begin(), clearMagic.end(), clearing.begin());
    write(marker, clearing); // Crash after durable intent, before deleting data.
    { Storage recovered(directory); need(recovered.open().accounts().empty(), "interrupted clear did not retain data"); }
    need(read(path) == original && read(marker) == normal, "interrupted clear changed original state");
    write(marker, clearing); std::filesystem::remove(path); // Crash after deleting data, before marker cleanup.
    {
        Storage recovered(directory);
        need(!std::filesystem::exists(marker), "confirmed clear marker was not cleaned up");
        recovered.initializeLocal(); (void)recovered.open();
    }
    std::filesystem::remove(path); // Ordinary missing data must still fail closed.
    {
        Storage missing(directory);
        rejects([&] { missing.open(); }); rejects([&] { missing.initializeLocal(); });
        need(std::filesystem::exists(marker), "ordinary missing vault was automatically reset");
    }
}
}
int main() {
    auto directory = std::filesystem::temp_directory_path() / ("pf2-clear-test-" + hex(randomBytes(12).data(), 12));
    int result = 0;
    try {
        platform::createPrivateDirectories(directory); clearing(directory); interrupted(directory / "interrupted");
        std::puts("PASS: verified backup required for local clear, cancellation, delete failure, backup switching and crash recovery");
    } catch (const std::exception &e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); result = 1; }
    std::error_code ignored; std::filesystem::remove_all(directory, ignored); return result;
}
