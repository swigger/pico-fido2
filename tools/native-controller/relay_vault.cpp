#include "relay_vault.h"
#include "credentials.h"
#include "device_names.h"
#include "relay_backup.h"
#include <algorithm>
#include <cstring>
#include <set>
#include <stdexcept>

namespace relay {
namespace {
constexpr size_t maxFile = 8 * 1024 * 1024;
constexpr unsigned char magic[8] = {'P','F','2','V','L','T','0','2'};
constexpr unsigned char lockMagic[8] = {'P','F','2','L','C','K','0','1'};
constexpr unsigned char movedMagic[8] = {'P','F','2','M','O','V','0','1'};
constexpr unsigned char clearMagic[8] = {'P','F','2','C','L','R','0','1'};
constexpr unsigned char hwmMagic[8] = {'P','F','2','H','W','M','0','1'};
void require(bool ok, const char *message = "安全端凭证库损坏或不兼容") {
    if (!ok) throw std::runtime_error(message);
}
struct Secret {
    Bytes b;
    explicit Secret(Bytes data) : b(std::move(data)) {}
    ~Secret() { if (!b.empty()) secureZero(b.data(), b.size()); }
};
constexpr const char *vaultPurpose = "Pico FIDO relay vault v1";
Bytes read(const std::filesystem::path &path, size_t limit = maxFile) {
    return platform::readFile(path, limit, "无法读取安全端凭证库；不会创建空库替代");
}
Bytes protect(const Bytes &b, bool encrypt) {
    return encrypt ? platform::protect(b, vaultPurpose) : platform::unprotect(b, vaultPurpose);
}
void put(Bytes &out, uint64_t n, unsigned width) {
    for (unsigned i = 0; i < width; ++i) out.push_back(static_cast<uint8_t>(n >> (i * 8)));
}
uint64_t get(const Bytes &b, size_t &pos, unsigned width) {
    require(pos <= b.size() && width <= b.size() - pos);
    uint64_t n = 0;
    for (unsigned i = 0; i < width; ++i) n |= static_cast<uint64_t>(b[pos++]) << (i * 8);
    return n;
}
ctap::Value flag(bool value) { ctap::Value v; v.type = ctap::Value::Boolean; v.number = value; return v; }
void validate(const Credential &r, bool verifyKey) {
    require(r.credentialId.size() == 32 && !r.userId.empty() && r.userId.size() <= 64 &&
        !r.rp.empty() && r.rp.size() <= 253 && r.userName.size() <= 64 && r.displayName.size() <= 64 &&
        r.privateKey.size() == 104);
    (void)widen(r.rp); (void)widen(r.userName); (void)widen(r.displayName);
    // Import verifies that public and private key halves agree, not just lengths.
    if (verifyKey) (void)Key::fromBlob(r.privateKey);
}
Bytes serialize(const Id &id, uint64_t generation, const std::vector<Credential> &records, const std::map<std::string, PinRecord> &pins, const Attestation &attestation) {
    require(records.size() <= Vault::capacity && generation);
    Secret output(Bytes(std::begin(magic), std::end(magic)));
    if (!attestation.privateKey.empty()) output.b[7] = '3';
    output.b.insert(output.b.end(), id.begin(), id.end()); put(output.b, generation, 8); put(output.b, records.size(), 4);
    std::set<Bytes> ids;
    for (const auto &r : records) {
        validate(r, false); require(ids.insert(r.credentialId).second);
        using V = ctap::Value;
        Secret body(ctap::encode(V::map({V::integer(1), V::blob(r.credentialId), V::integer(2), V::string(r.rp),
            V::integer(3), V::blob(r.userId), V::integer(4), V::string(r.userName),
            V::integer(5), V::string(r.displayName), V::integer(6), V::blob(r.privateKey),
            V::integer(7), V::integer(r.counter), V::integer(8), flag(r.discoverable)})));
        put(output.b, body.b.size(), 4); output.b.insert(output.b.end(), body.b.begin(), body.b.end());
    }
    require(pins.size() <= 256); put(output.b, pins.size(), 2);
    for (const auto &[serial, pin] : pins) {
        require(validDeviceSerial(serial) && pin.salt.size() == 32 && pin.verifier.size() == 32 && pin.retries <= 8);
        require(serial.find_first_of("ABCDEF") == std::string::npos);
        output.b.insert(output.b.end(), serial.begin(), serial.end());
        output.b.insert(output.b.end(), pin.salt.begin(), pin.salt.end());
        output.b.insert(output.b.end(), pin.verifier.begin(), pin.verifier.end()); output.b.push_back(pin.retries);
    }
    if (output.b[7] == '3') {
        require(attestation.privateKey.size() == 104 && !attestation.certificate.empty() && attestation.certificate.size() <= 2048);
        output.b.insert(output.b.end(), attestation.privateKey.begin(), attestation.privateKey.end());
        put(output.b, attestation.certificate.size(), 2);
        output.b.insert(output.b.end(), attestation.certificate.begin(), attestation.certificate.end());
    }
    return std::move(output.b);
}
std::vector<Credential> parse(const Bytes &b, const Id &id, uint64_t &generation, std::map<std::string, PinRecord> &pins, Attestation &attestation) {
    attestation = {};
    require(b.size() >= 36 && std::equal(std::begin(magic), std::end(magic) - 1, b.begin()) && (b[7] >= '1' && b[7] <= '3') &&
        std::equal(id.begin(), id.end(), b.begin() + 8));
    size_t pos = 24; generation = get(b, pos, 8); auto count = get(b, pos, 4);
    require(generation && count <= Vault::capacity);
    std::vector<Credential> records; std::set<Bytes> ids;
    for (uint64_t i = 0; i < count; ++i) {
        auto n = get(b, pos, 4); require(n <= 2048 && n <= b.size() - pos);
        Secret body(Bytes(b.begin() + pos, b.begin() + pos + static_cast<size_t>(n))); pos += static_cast<size_t>(n);
        auto v = ctap::decode(body.b);
        require(v.type == ctap::Value::Map && v.items.size() == 16);
        auto blob = [&](int k) { const auto &a = v.at(k); require(a.type == ctap::Value::ByteString); return a.bytes; };
        auto text = [&](int k) { const auto &a = v.at(k); require(a.type == ctap::Value::Text); return a.text; };
        Credential r; r.credentialId = blob(1); r.rp = text(2); r.userId = blob(3);
        r.userName = text(4); r.displayName = text(5); r.privateKey = blob(6);
        r.counter = static_cast<uint32_t>(v.at(7).count(UINT32_MAX));
        require(v.at(8).type == ctap::Value::Boolean); r.discoverable = v.at(8).number != 0;
        validate(r, true); require(ids.insert(r.credentialId).second); records.push_back(std::move(r));
    }
    if (b[7] >= '2') {
        auto countPins = get(b, pos, 2); require(countPins <= 256);
        for (uint64_t i = 0; i < countPins; ++i) {
            require(pos <= b.size() && b.size() - pos >= 81);
            std::string serial(reinterpret_cast<const char *>(b.data() + pos), 16); pos += 16;
            require(validDeviceSerial(serial) && serial.find_first_of("ABCDEF") == std::string::npos && !pins.count(serial));
            PinRecord pin; pin.salt.assign(b.begin() + pos, b.begin() + pos + 32); pos += 32;
            pin.verifier.assign(b.begin() + pos, b.begin() + pos + 32); pos += 32; pin.retries = b[pos++];
            require(pin.retries <= 8); pins.emplace(serial, std::move(pin));
        }
    }
    if (b[7] == '3') {
        require(pos <= b.size() && b.size() - pos >= 106);
        attestation.privateKey.assign(b.begin() + pos, b.begin() + pos + 104); pos += 104;
        auto n = get(b, pos, 2); require(n && n <= 2048 && n == b.size() - pos);
        attestation.certificate.assign(b.begin() + pos, b.end()); pos = b.size();
        attestation.validate();
    }
    require(pos == b.size()); return records;
}
void atomicWrite(const std::filesystem::path &path, const Bytes &cipher, bool initial, size_t limit = maxFile) {
    // The lock is a separate, persistent file: atomic replacement cannot release it.
    platform::publishFile(path, cipher, !initial, "凭证库写入、同步或替换失败；此次操作不会返回成功");
    require(read(path, limit) == cipher, "凭证库写后校验失败；必须重新打开并检查");
}
std::filesystem::path lockPath(const std::filesystem::path &path) {
    auto result = path; result += L".lock"; return result;
}
void initialize(const std::filesystem::path &path, const Id &id, const Bytes &plain) {
    require(!std::filesystem::exists(path), "凭证库已存在，不能覆盖");
    // Encrypt before creating the durable initialization marker. Once the marker
    // exists, failures deliberately leave it in place to prevent accidental reset.
    auto cipher = protect(plain, true);
    require(cipher.size() <= maxFile);
    if (!path.parent_path().empty()) platform::createPrivateDirectories(path.parent_path());
    platform::FileLock h(lockPath(path), platform::FileLock::Mode::CreateNew, "凭证库已初始化、正在使用或初始化曾中断；不会自动重建");
    Bytes marker(std::begin(lockMagic), std::end(lockMagic)); marker.insert(marker.end(), id.begin(), id.end());
    h.write(marker);
    atomicWrite(path, cipher, true);
}
}
Credential &Credential::operator=(Credential other) noexcept {
    using std::swap;
    swap(static_cast<Account &>(*this), static_cast<Account &>(other)); privateKey.swap(other.privateKey); return *this;
}
Credential::~Credential() { if (!privateKey.empty()) secureZero(privateKey.data(), privateKey.size()); }
PinRecord::~PinRecord() { if (!verifier.empty()) secureZero(verifier.data(), verifier.size()); }
PinRecord &PinRecord::operator=(PinRecord other) noexcept {
    salt.swap(other.salt); verifier.swap(other.verifier); std::swap(retries, other.retries); return *this;
}
std::filesystem::path Vault::defaultPath() { return platform::dataDirectory() / "safe-end" / ("credentials-v1" + platform::protectedExtension()); }
struct Vault::CloudState {
    struct Password {
        std::wstring value;
        explicit Password(const std::wstring &p) : value(p) {}
        ~Password() { if (!value.empty()) secureZero(value.data(), value.size() * sizeof(wchar_t)); }
    } password;
    std::unique_ptr<CloudStorage> storage;
    bool transaction = false;
    std::string nameSpace;
    CloudLaunch launch;
    std::function<bool()> canceled;
    uint64_t head = 0;
    Bytes snapshotHash;
    std::filesystem::path highWater;
    Id identity{};
    CloudState(const std::string &nameSpace, const std::wstring &p, const CloudLaunch &launch)
        : password(p), nameSpace(nameSpace), launch(launch), highWater(launch.highWater), identity(CloudStorage::identity(nameSpace)) {}
    // Generation is the authenticated plaintext revision, so a replayed older
    // ciphertext cannot pass by carrying a newer coordinator head number.
    void notOlder(uint64_t generation) const {
        if (highWater.empty() || !std::filesystem::exists(highWater)) return;
        auto b = platform::readFile(highWater, 32, "云端凭证库版本记录损坏");
        require(b.size() == 32 && !memcmp(b.data(), "PF2HWM01", 8) && std::equal(identity.begin(), identity.end(), b.begin() + 8),
            "云端凭证库版本记录损坏");
        uint64_t seen = 0; for (unsigned i = 0; i < 8; ++i) seen |= uint64_t(b[24 + i]) << (8 * i);
        require(generation >= seen, "云端凭证库比本机已见过的版本更旧（可能被回滚）；已拒绝打开，不会覆盖");
    }
    void record(uint64_t generation) const {
        if (highWater.empty()) return;
        Bytes b(std::begin(hwmMagic), std::end(hwmMagic)); b.insert(b.end(), identity.begin(), identity.end());
        for (unsigned i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>(generation >> (8 * i)));
        platform::publishFile(highWater, b, true, "无法记录云端凭证库版本");
    }
};
Vault::Vault(CloudTag) {}
std::unique_ptr<Vault> Vault::openCloud(const std::string &nameSpace, const std::wstring &password, const CloudLaunch &launch) {
    auto vault = std::unique_ptr<Vault>(new Vault(CloudTag{})); vault->identity = CloudStorage::identity(nameSpace);
    vault->cloud = std::make_unique<CloudState>(nameSpace, password, launch);
    Transaction transaction(*vault);
    vault->check(); return vault;
}
std::unique_ptr<Vault> Vault::createCloud(const std::string &nameSpace, const std::wstring &password, const CloudLaunch &launch) {
    return seedCloud(nameSpace, password, launch, nullptr, false);
}
std::unique_ptr<Vault> Vault::seedCloud(const std::string &nameSpace, const std::wstring &password, const CloudLaunch &launch, Vault *source, bool resume, const Bytes &creationToken) {
    auto vault = std::unique_ptr<Vault>(new Vault(CloudTag{})); vault->identity = CloudStorage::identity(nameSpace);
    if (source) {
        require(!source->cloud && source->identity == vault->identity);
        vault->records = source->records; vault->pins = source->pins; vault->attestation = source->attestation; vault->generation = source->generation;
    } else vault->generation = 1;
    Secret plain(serialize(vault->identity, vault->generation, vault->records, vault->pins, vault->attestation));
    // Reject an invalid password before reserving the permanent cloud marker.
    auto cipher = backup::encrypt(plain.b, password);
    vault->cloud = std::make_unique<CloudState>(nameSpace, password, launch);
    vault->cloud->storage = std::make_unique<CloudStorage>(nameSpace, launch);
    auto snapshot = vault->cloud->storage->open(!resume, resume, creationToken);
    vault->cloud->transaction = true;
    if (snapshot.generation) {
        require(!source || source->retired, "迁移状态不一致；不会合并或替换任何副本");
        Secret existing(backup::decrypt(snapshot.encrypted, password));
        vault->pins.clear(); vault->records = parse(existing.b, vault->identity, vault->generation, vault->pins, vault->attestation);
        vault->cloud->notOlder(vault->generation);
        vault->cloud->head = snapshot.generation;
        vault->cloud->snapshotHash = hash(snapshot.encrypted);
    } else {
        if (source) source->retireLocal();
        vault->cloud->head = vault->cloud->storage->commit(0, cipher);
        vault->cloud->snapshotHash = hash(cipher);
    }
    vault->cloud->record(vault->generation);
    vault->check(); vault->endTransaction(); return vault;
}
void Vault::create(const std::filesystem::path &path) {
    Id id{}; auto random = randomBytes(16); std::copy(random.begin(), random.end(), id.begin());
    Secret plain(serialize(id, 1, {}, {}, {})); initialize(path, id, plain.b);
}
void Vault::restoreBackup(const std::filesystem::path &source, const std::wstring &password, const std::filesystem::path &destination) {
    require(!std::filesystem::exists(destination) && !std::filesystem::exists(lockPath(destination)),
        "恢复目标已初始化；不能覆盖、合并或自动重置");
    Secret plain(backup::decrypt(read(source, backup::maxPlaintext + backup::overhead), password));
    require(plain.b.size() >= 36); Id id{}; std::copy_n(plain.b.begin() + 8, 16, id.begin());
    uint64_t revision = 0; std::map<std::string, PinRecord> pins; Attestation attestation;
    // Validate the entire schema and each EC key before touching the destination.
    auto records = parse(plain.b, id, revision, pins, attestation);
    Secret current(serialize(id, revision, records, pins, attestation)); initialize(destination, id, current.b);
}
void Vault::exportBackup(const std::filesystem::path &destination, const std::wstring &password) {
    std::lock_guard<std::mutex> guard(transactionMutex); Transaction transaction(*this); check(); checkDisk();
    require(!std::filesystem::exists(destination), "备份文件已存在；请选择新的文件名");
    Secret plain(serialize(identity, generation, records, pins, attestation)); auto cipher = backup::encrypt(plain.b, password);
    checkDisk(); atomicWrite(destination, cipher, true, backup::maxPlaintext + backup::overhead);
}
void Vault::verifyBackupForDetach(const std::filesystem::path &archive, const std::wstring &password) {
    std::lock_guard<std::mutex> guard(transactionMutex);
    require(cloud != nullptr); check();
    // Verify the exported authenticated snapshot, without acquiring another
    // remote lease: detaching never deletes or replaces the remote vault.
    Secret saved(backup::decrypt(read(archive, backup::maxPlaintext + backup::overhead), password));
    Secret current(serialize(identity, generation, records, pins, attestation));
    require(saved.b == current.b, "备份与本次打开的云端库快照不一致；请重新创建备份后再解除绑定");
}
void Vault::archiveRetiredLocal(const std::filesystem::path &path) {
    auto markerPath = lockPath(path);
    if (!std::filesystem::exists(path) && !std::filesystem::exists(markerPath)) return;
    const char *error = "无法保留已迁移的本机旧副本；未初始化新库";
    platform::FileLock marker(markerPath, platform::FileLock::Mode::OpenExisting, error);
    require(marker.size() == 24, error); auto bytes = marker.read(24);
    require(std::equal(std::begin(movedMagic), std::end(movedMagic), bytes.begin()),
        "已有本机凭证库或初始化标记；不会覆盖或自动重置");
    auto archive = path.parent_path() / ("retired-local-" + hex(bytes.data() + 8, 16)) / path.filename();
    platform::createPrivateDirectories(archive.parent_path());
    auto preserve = [&](const std::filesystem::path &destination, const Bytes &data) {
        if (!std::filesystem::exists(destination)) platform::publishFile(destination, data, false, error);
        require(read(destination) == data, error);
    };
    if (std::filesystem::exists(path)) {
        preserve(archive, read(path));
        preserve(lockPath(archive), bytes);
        platform::removeFileChecked(path, error);
    } else {
        // Retry a confirmed switch interrupted after archiving/removing the
        // data but before removing its retired marker. Never recreate old data.
        require(!read(archive).empty() && read(lockPath(archive)) == bytes, error);
    }
    marker = {};
    platform::removeFileChecked(markerPath, error);
}
void Vault::recoverLocalClear(const std::filesystem::path &path) {
    auto markerPath = lockPath(path);
    if (!std::filesystem::exists(markerPath)) return;
    platform::FileLock marker(markerPath, platform::FileLock::Mode::OpenExisting, "本机库正在使用，无法检查清空状态");
    if (marker.size() != 24) return;
    auto bytes = marker.read(24);
    if (!std::equal(std::begin(clearMagic), std::end(clearMagic), bytes.begin())) return;
    if (std::filesystem::exists(path)) {
        // Interrupted before deleting the data: retain the original vault.
        std::copy(std::begin(lockMagic), std::end(lockMagic), bytes.begin());
        marker.write(bytes); require(marker.read(24) == bytes, "无法恢复本机库的锁标记");
    } else {
        // Only an explicitly confirmed clear can create this durable marker.
        // A normal missing/corrupt vault still fails closed, as before.
        marker = {};
        platform::removeFileChecked(markerPath, "备份已保存，但本机库锁标记尚未清理；请重新打开后重试");
    }
}
void Vault::clearLocalAfterBackup(const std::filesystem::path &archive, const std::wstring &password,
                                const std::function<bool()> &canceled) {
    std::lock_guard<std::mutex> guard(transactionMutex);
    require(!cloud, "仅支持在备份后清空本机库"); check(); checkDisk();
    // Re-read and decrypt after confirmation. An old/different/deleted/corrupt
    // backup must never authorize deletion, even when its namespace matches.
    Secret saved(backup::decrypt(read(archive, backup::maxPlaintext + backup::overhead), password));
    Secret current(serialize(identity, generation, records, pins, attestation));
    require(saved.b == current.b, "备份与当前本机库不一致；请重新创建备份后再清空");
    check(); checkDisk();
    require(!canceled || !canceled(), "操作已取消，本机库未清空");
    Bytes marker(std::begin(clearMagic), std::end(clearMagic)); marker.insert(marker.end(), identity.begin(), identity.end());
    faulted = true;
    lock.write(marker); require(lock.read(24) == marker, "无法确认本机库的清空标记；未删除凭证库");
    platform::removeFileChecked(path, "无法删除本机凭证库；备份已保存，请关闭占用文件的程序后重试");
    records.clear(); pins.clear(); attestation = {};
    lock = {}; // The backend lock still excludes every production storage owner.
    platform::removeFileChecked(lockPath(path), "备份已保存，但本机库锁标记尚未清理；请重新打开后重试");
}
Vault::Vault(const std::filesystem::path &p) : Vault(p, false) {}
Vault::Vault(const std::filesystem::path &p, bool allowRetired) : path(p) {
    platform::FileLock h(lockPath(path), platform::FileLock::Mode::OpenExisting, "凭证库未初始化或已被另一个安全端占用");
    require(h.size() == 24); auto marker = h.read(24);
    retired = std::equal(std::begin(movedMagic), std::end(movedMagic), marker.begin());
    require((allowRetired && retired) || std::equal(std::begin(lockMagic), std::end(lockMagic), marker.begin()),
        "本机凭证库已迁移或标记损坏；不会启用旧副本");
    std::copy(marker.begin() + 8, marker.end(), identity.begin());
    auto cipher = read(path); savedDigest = hash(cipher);
    Secret plain(protect(cipher, false)); records = parse(plain.b, identity, generation, pins, attestation);
    faulted = retired; lock = std::move(h);
}
void Vault::retireLocal() {
    require(!cloud); checkDisk();
    if (retired) return;
    check(); faulted = true;
    Bytes marker(std::begin(movedMagic), std::end(movedMagic)); marker.insert(marker.end(), identity.begin(), identity.end());
    try { lock.write(marker); } catch (...) { throw std::runtime_error("无法持久停用本机副本；迁移已停止"); }
    require(lock.read(24) == marker);
    retired = true;
}
std::string Vault::namespaceId() const { std::lock_guard<std::mutex> guard(transactionMutex); check(); return hex(identity.data(), identity.size()); }
Vault::~Vault() { records.clear(); }
void Vault::check() const {
    require(!faulted, "凭证库写入结果不确定，已停止服务；必须重新打开并检查");
    if (backendCheck) { try { backendCheck(); } catch (...) { faulted = true; throw; } }
    if (cloud && cloud->transaction) {
        try { cloud->storage->check(); }
        catch (...) { faulted = true; throw; }
    }
}
void Vault::beginTransaction() {
    check();
    if (!cloud) { checkDisk(); return; }
    require(!cloud->transaction, "云端事务已开始");
    // Failure to acquire/read has made no mutation and may be retried by a new
    // command. A failed commit, by contrast, permanently faults this vault.
    auto storage = std::move(cloud->storage);
    if (!storage) storage = std::make_unique<CloudStorage>(cloud->nameSpace, cloud->launch);
    storage->cancellation(cloud->canceled);
    CloudSnapshot snapshot;
    try { snapshot = cloud->snapshotHash.empty() ? storage->open(false) : storage->openCached(cloud->head, cloud->snapshotHash); }
    catch (const CloudIntegrityError &) { faulted = true; throw; }
    try {
        if (snapshot.encrypted.empty()) {
            cloud->notOlder(generation);
            cloud->storage = std::move(storage); cloud->transaction = true; return;
        }
        Secret plain(backup::decrypt(snapshot.encrypted, cloud->password.value));
        uint64_t freshGeneration = 0; std::map<std::string, PinRecord> freshPins; Attestation freshAttestation;
        auto freshRecords = parse(plain.b, identity, freshGeneration, freshPins, freshAttestation);
        require(freshGeneration >= generation, "云端凭证库版本回退，已拒绝操作");
        cloud->notOlder(freshGeneration); cloud->record(freshGeneration);
        records = std::move(freshRecords); pins = std::move(freshPins); attestation = std::move(freshAttestation); generation = freshGeneration;
        cloud->snapshotHash = hash(snapshot.encrypted);
        cloud->head = snapshot.generation; cloud->storage = std::move(storage); cloud->transaction = true;
    } catch (...) { faulted = true; throw; }
}
void Vault::endTransaction() noexcept {
    if (!cloud || !cloud->transaction) return;
    // Release the lease, retaining the helper/HTTP pool for at most five idle minutes.
    // No commit is retried, even if its acknowledgement was lost.
    try { cloud->storage->release(); } catch (...) { cloud->storage.reset(); }
    cloud->transaction = false;
}
void Vault::cancellation(std::function<bool()> canceled) {
    if (!cloud) return;
    cloud->canceled = std::move(canceled);
    if (cloud->storage) cloud->storage->cancellation(cloud->canceled);
}
void Vault::checkDisk() {
    if (cloud) { check(); return; }
    try { require(hash(read(path)) == savedDigest, "凭证库在持锁期间发生变化，已停止服务"); }
    catch (...) { faulted = true; throw; }
}
std::vector<Account> Vault::accounts() const {
    std::lock_guard<std::mutex> guard(transactionMutex);
    Transaction transaction(*const_cast<Vault *>(this));
    check(); std::vector<Account> out; for (const auto &r : records) out.push_back(r); check(); return out;
}
std::vector<Account> Vault::displayAccounts() const {
    std::lock_guard<std::mutex> guard(transactionMutex);
    check(); std::vector<Account> out; for (const auto &r : records) out.push_back(r); return out;
}
bool Vault::contains(const std::string &rp, const std::string &name) const {
    std::lock_guard<std::mutex> guard(transactionMutex);
    Transaction transaction(*const_cast<Vault *>(this));
    check(); require(!rp.empty() && !name.empty(), "查询必须同时指定网站与完整账号名");
    bool found = std::any_of(records.begin(), records.end(), [&](const auto &r) { return r.rp == rp && r.userName == name; });
    check(); return found;
}
void Vault::commit(std::vector<Credential> next) {
    commitAll(std::move(next), pins, attestation);
}
void Vault::commit(std::vector<Credential> next, Attestation nextAttestation) {
    commitAll(std::move(next), pins, std::move(nextAttestation));
}
bool Vault::resetDevicePin(std::string serial) {
    std::lock_guard<std::mutex> guard(transactionMutex); Transaction transaction(*this); check(); require(validDeviceSerial(serial), "设备序列号不正确");
    for (auto &c : serial) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    auto next = pins; if (!next.erase(serial)) return false;
    commitPins(std::move(next)); return true;
}
void Vault::commitPins(std::map<std::string, PinRecord> next) {
    commitAll(records, std::move(next), attestation);
}
void Vault::commitAll(std::vector<Credential> next, std::map<std::string, PinRecord> nextPins, Attestation nextAttestation) {
    check(); require(generation != UINT64_MAX, "凭证库版本号已用尽");
    Secret plain(serialize(identity, generation + 1, next, nextPins, nextAttestation));
    if (cloud) {
        try {
            auto cipher = backup::encrypt(plain.b, cloud->password.value);
            require(cloud->storage != nullptr && cloud->transaction, "云端写入必须持有事务锁");
            cloud->head = cloud->storage->commit(cloud->head, cipher);
            cloud->record(generation + 1);
            cloud->snapshotHash = hash(cipher);
        } catch (...) { faulted = true; throw; }
        records = std::move(next); pins = std::move(nextPins); attestation = std::move(nextAttestation); ++generation; return;
    }
    auto cipher = protect(plain.b, true);
    auto nextDigest = hash(cipher);
    try {
        checkDisk();
        atomicWrite(path, cipher, false);
    }
    catch (...) { faulted = true; throw; } // Never keep serving a possibly stale snapshot.
    savedDigest = std::move(nextDigest); records = std::move(next); pins = std::move(nextPins); attestation = std::move(nextAttestation); ++generation;
}
}
