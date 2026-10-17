#include "relay_storage.h"
#include "relay_backup.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace relay {
namespace {
void need(bool ok, const char *message = "存储选择损坏或不可用；不会回退到本机库") { if (!ok) throw std::runtime_error(message); }
constexpr const char *selectionPurpose = "Pico FIDO backend selection v1";
constexpr const char *codePurpose = "Pico FIDO cloud recovery code v1";
struct SecretBytes { Bytes value; ~SecretBytes() { wipe(value); } };
struct SecretCode { std::wstring value; ~SecretCode() { wipe(value); } };
Bytes read(const std::filesystem::path &path) {
    return platform::readFile(path, 4096, "存储选择损坏或不可用；不会回退到本机库");
}
Bytes protect(const Bytes &input, bool encrypt) {
    auto out = encrypt ? platform::protect(input, selectionPurpose) : platform::unprotect(input, selectionPurpose);
    need(out.size() <= 4096); return out;
}
void write(const std::filesystem::path &path, const Bytes &bytes, bool first) {
    platform::publishFile(path, bytes, !first, "存储选择损坏或不可用；不会回退到本机库");
    need(read(path) == bytes);
}
Bytes encode(const Id &identity, const StorageChoice &choice) {
    Bytes bytes(112); memcpy(bytes.data(), "PF2BCK01", 8); std::copy(identity.begin(), identity.end(), bytes.begin() + 8);
    bytes[24] = static_cast<uint8_t>(choice.kind);
    need(bytes[24] <= static_cast<uint8_t>(StorageKind::DetachingCloud));
    if (choice.kind == StorageKind::Local || choice.kind == StorageKind::Unbound) need(choice.nameSpace.empty());
    else { auto id = CloudStorage::identity(choice.nameSpace); std::copy(id.begin(), id.end(), bytes.begin() + 32); }
    if (choice.kind == StorageKind::MovingToCloud) {
        need(choice.sourceDigest.size() == 32); std::copy(choice.sourceDigest.begin(), choice.sourceDigest.end(), bytes.begin() + 48);
    } else need(choice.sourceDigest.empty());
    if (choice.kind == StorageKind::InitializingCloud || choice.kind == StorageKind::MovingToCloud) {
        need(choice.creationToken.size() == 32); std::copy(choice.creationToken.begin(), choice.creationToken.end(), bytes.begin() + 80);
    } else need(choice.creationToken.empty());
    return bytes;
}
StorageChoice decode(const Id &identity, const Bytes &plain) {
    need(plain.size() == 112 && !memcmp(plain.data(), "PF2BCK01", 8) && std::equal(identity.begin(), identity.end(), plain.begin() + 8));
    StorageChoice choice; choice.kind = static_cast<StorageKind>(plain[24]);
    if (choice.kind != StorageKind::Local && choice.kind != StorageKind::Unbound) choice.nameSpace = hex(plain.data() + 32, 16);
    if (choice.kind == StorageKind::MovingToCloud) choice.sourceDigest.assign(plain.begin() + 48, plain.begin() + 80);
    if (choice.kind == StorageKind::InitializingCloud || choice.kind == StorageKind::MovingToCloud) choice.creationToken.assign(plain.begin() + 80, plain.end());
    need(encode(identity, choice) == plain); return choice; // Includes reserved/unused bytes.
}
void passwordValid(const std::wstring &password) {
    // Validate before writing a migration/initialization intent or retiring data.
    (void)backup::encrypt(Bytes(36), password);
}
}
struct Storage::State {
    std::filesystem::path directory, file, local;
    CloudLaunch launch;
    platform::FileLock lock;
    Id identity{};
    StorageChoice choice;
    Bytes digest;
    mutable bool faulted = false;
    State(const std::filesystem::path &dir, const CloudLaunch &launch) : directory(dir), file(dir / ("backend-v1" + platform::protectedExtension())), local(dir / ("credentials-v1" + platform::protectedExtension())), launch(launch) {
        need(dir.is_absolute()); platform::createPrivateDirectories(dir);
        lock = platform::FileLock(dir / "backend-v1.lock", platform::FileLock::Mode::OpenAlways, "存储设置或安全端正在使用；请先关闭自己的服务窗口");
        if (lock.created()) {
            need(!std::filesystem::exists(file)); auto random = randomBytes(16); std::copy(random.begin(), random.end(), identity.begin());
            Bytes bytes(24); memcpy(bytes.data(), "PF2BSEL1", 8); std::copy(identity.begin(), identity.end(), bytes.begin() + 8);
            auto cipher = protect(encode(identity, choice), true);
            lock.write(bytes);
            write(file, cipher, true); digest = hash(cipher);
        } else {
            need(lock.size() == 24); auto bytes = lock.read(24); need(!memcmp(bytes.data(), "PF2BSEL1", 8));
            std::copy_n(bytes.begin() + 8, 16, identity.begin()); auto cipher = read(file);
            choice = decode(identity, protect(cipher, false)); digest = hash(cipher);
        }
    }
    void check() const {
        need(!faulted);
        try { need(hash(read(file)) == digest); } catch (...) { faulted = true; throw; }
    }
    void save(const StorageChoice &next) {
        check(); auto cipher = protect(encode(identity, next), true);
        faulted = true; write(file, cipher, false); choice = next; digest = hash(cipher); faulted = false;
    }
    void emptyLocal() const {
        auto marker = local; marker += ".lock";
        need(!std::filesystem::exists(local) && !std::filesystem::exists(marker), "本机凭证库已经初始化；请迁移它，不能直接切换到另一份库");
    }
    CloudLaunch launchFor(const std::string &nameSpace) const {
        auto out = launch; out.highWater = directory / ("cloud-" + nameSpace + ".generation"); return out;
    }
    void localOnly() const { check(); need(choice.kind == StorageKind::Local, "当前不是本机存储；不会创建或启用本机副本"); }
    std::filesystem::path codePath() const {
        check(); (void)CloudStorage::identity(choice.nameSpace);
        return directory / ("cloud-code-" + choice.nameSpace + platform::protectedExtension());
    }
    Bytes codeHeader() const {
        Bytes out{'P','F','2','C','O','D','0','1'};
        out.insert(out.end(), identity.begin(), identity.end());
        auto ns = CloudStorage::identity(choice.nameSpace); out.insert(out.end(), ns.begin(), ns.end()); return out;
    }
    void cloudSelectable() const {
        check(); need(choice.kind == StorageKind::Local || choice.kind == StorageKind::Unbound, "请先备份并解除当前云端库的本机绑定");
        if (choice.kind == StorageKind::Local) emptyLocal();
        // An explicitly detached cloud may leave a retired migration source.
        // It stays untouched and is never selected or opened as a local vault.
    }
};
std::filesystem::path Storage::defaultDirectory() { return Vault::defaultPath().parent_path(); }
Storage::Storage(const std::filesystem::path &directory, const CloudLaunch &launch) : state(std::make_unique<State>(directory, launch)) {
    if (state->choice.kind == StorageKind::Local) Vault::recoverLocalClear(state->local);
    if (state->choice.kind == StorageKind::DetachingCloud) finishDetach();
}
Storage::~Storage() = default;
StorageChoice Storage::choice() const { state->check(); return state->choice; }
std::wstring Storage::rememberedCloudCode() const {
    auto path = state->codePath();
    if (!std::filesystem::exists(path)) return {};
    auto sealed = platform::readFile(path, 4096, "无法读取已记住的恢复码");
    SecretBytes plain{platform::unprotect(sealed, codePurpose)};
    auto header = state->codeHeader();
    need(plain.value.size() == header.size() + 26 && std::equal(header.begin(), header.end(), plain.value.begin()), "已记住的恢复码损坏或不属于当前云端库");
    SecretCode code{std::wstring(plain.value.begin() + header.size(), plain.value.end())};
    return backup::recoveryCode(code.value);
}
void Storage::rememberCloudCode(const std::wstring &value) {
    need(state->choice.kind == StorageKind::Cloud && opened != nullptr, "请先验证并打开云端库，再记住恢复码");
    SecretCode code{backup::recoveryCode(value)};
    SecretBytes plain{state->codeHeader()}; plain.value.insert(plain.value.end(), code.value.begin(), code.value.end());
    auto sealed = platform::protect(plain.value, codePurpose);
    platform::publishFile(state->codePath(), sealed, true, "无法安全保存恢复码；请重试或取消勾选记住");
}
void Storage::forgetCloudCode() {
    auto path = state->codePath();
    if (std::filesystem::exists(path)) platform::removeFileChecked(path, "无法清除已记住的恢复码；请检查本机数据目录权限");
}
std::string Storage::localNamespace() const { state->localOnly(); Vault local(state->local); return local.namespaceId(); }
void Storage::attach() { opened->backendCheck = [this] { state->check(); }; }
Vault &Storage::open(const std::wstring &password) {
    state->check(); if (opened) { opened->check(); return *opened; }
    if (state->choice.kind == StorageKind::Local) opened = std::make_unique<Vault>(state->local);
    else if (state->choice.kind == StorageKind::Cloud) opened = Vault::openCloud(state->choice.nameSpace, password, state->launchFor(state->choice.nameSpace));
    else if (state->choice.kind == StorageKind::Unbound) throw std::runtime_error("已解除本机云端绑定；请配置并连接另一份云端库");
    else throw std::runtime_error("云端初始化或迁移尚未完成；请显式恢复该操作，不会打开旧副本");
    attach(); return *opened;
}
void Storage::initializeLocal() { state->localOnly(); need(!opened); Vault::create(state->local); }
void Storage::restoreLocal(const std::filesystem::path &archive, const std::wstring &password) { state->localOnly(); need(!opened); Vault::restoreBackup(archive, password, state->local); }
void Storage::clearLocalAfterBackup(const std::filesystem::path &archive, const std::wstring &password,
                                   const std::function<bool()> &canceled) {
    state->localOnly(); need(opened != nullptr, "请先打开本机凭证库");
    try { opened->clearLocalAfterBackup(archive, password, canceled); }
    catch (...) {
        if (!opened->healthy()) { opened.reset(); Vault::recoverLocalClear(state->local); }
        throw;
    }
    opened.reset();
}
void Storage::detachCloudAfterBackup(const std::filesystem::path &archive, const std::wstring &password,
                                    const std::function<bool()> &canceled) {
    state->check(); need(state->choice.kind == StorageKind::Cloud && opened != nullptr, "请先打开云端凭证库");
    opened->verifyBackupForDetach(archive, password);
    need(!canceled || !canceled(), "操作已取消，云端绑定已保留");
    // Once recorded, a restart may finish this confirmed LOCAL removal. Never
    // claim success or silently fall back if profile deletion/selection fails.
    state->save({StorageKind::DetachingCloud, state->choice.nameSpace, {}, {}});
    opened.reset(); // Stop the helper, release its profile lock and wipe secrets.
    finishDetach();
}
void Storage::finishDetach() {
    state->check(); need(state->choice.kind == StorageKind::DetachingCloud && !opened);
    forgetCloudCode();
    CloudStorage::forgetProfile(state->choice.nameSpace, state->launch);
    // Keep non-secret rollback guards, profile lock markers and retired local
    // files. They are not an active cloud association and must not be revived.
    state->save({StorageKind::Unbound, {}, {}, {}});
}
void Storage::finishCloud() { state->save({StorageKind::Cloud, opened->namespaceId(), {}, {}}); attach(); }
void Storage::initializeCloud(const std::string &nameSpace, const std::wstring &password) {
    state->cloudSelectable(); need(!opened); (void)CloudStorage::identity(nameSpace); passwordValid(password);
    state->save({StorageKind::InitializingCloud, nameSpace, {}, randomBytes(32)});
    opened = Vault::seedCloud(nameSpace, password, state->launchFor(nameSpace), nullptr, false, state->choice.creationToken); finishCloud();
}
void Storage::selectCloud(const std::string &nameSpace, const std::wstring &password) {
    state->cloudSelectable(); need(!opened);
    opened = Vault::openCloud(nameSpace, password, state->launchFor(nameSpace)); finishCloud();
}
void Storage::migrateCloud(const std::wstring &password) {
    state->localOnly(); need(!opened); passwordValid(password); Vault source(state->local);
    state->save({StorageKind::MovingToCloud, source.namespaceId(), source.savedDigest, randomBytes(32)});
    opened = Vault::seedCloud(state->choice.nameSpace, password, state->launchFor(state->choice.nameSpace), &source, false, state->choice.creationToken); finishCloud();
}
void Storage::resume(const std::wstring &password) {
    state->check(); need(!opened); passwordValid(password);
    if (state->choice.kind == StorageKind::InitializingCloud) {
        opened = Vault::seedCloud(state->choice.nameSpace, password, state->launchFor(state->choice.nameSpace), nullptr, true, state->choice.creationToken);
    } else if (state->choice.kind == StorageKind::MovingToCloud) {
        Vault source(state->local, true); need(source.savedDigest == state->choice.sourceDigest && hex(source.identity.data(), 16) == state->choice.nameSpace);
        opened = Vault::seedCloud(state->choice.nameSpace, password, state->launchFor(state->choice.nameSpace), &source, true, state->choice.creationToken);
    } else throw std::runtime_error("没有待恢复的云端初始化或迁移");
    finishCloud();
}
}
