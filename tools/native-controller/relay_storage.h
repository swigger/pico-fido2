#pragma once
#include "relay_vault.h"

namespace relay {
enum class StorageKind : uint8_t { Local, Cloud, InitializingCloud, MovingToCloud, Unbound, DetachingCloud };
struct StorageChoice {
    StorageKind kind = StorageKind::Local;
    std::string nameSpace;
    Bytes sourceDigest;
    Bytes creationToken; // Only for an explicit pending initialization/migration.
};
// The selection lock outlives the opened vault. All production safe-end commands
// use this owner so selection cannot change under a live service or approval.
class Storage {
public:
    static std::filesystem::path defaultDirectory();
    explicit Storage(const std::filesystem::path &directory = defaultDirectory(), const CloudLaunch &launch = {});
    ~Storage();
    Storage(const Storage &) = delete;
    Storage &operator=(const Storage &) = delete;
    StorageChoice choice() const;
    std::string localNamespace() const;
    Vault &open(const std::wstring &password = {});
    // Opt-in GUI recovery code, sealed with the OS user's data-protection key.
    // Bound to this storage identity and cloud namespace. Caller wipes returned code.
    std::wstring rememberedCloudCode() const;
    void rememberCloudCode(const std::wstring &code);
    void forgetCloudCode();
    // Explicitly selects local storage after cloud detach; never revives a
    // retired migration source or overwrites an existing local vault.
    void initializeLocal();
    void restoreLocal(const std::filesystem::path &archive, const std::wstring &password);
    // Explicit confirmation belongs to the caller. Requires an opened local
    // vault and a readable backup containing its exact current state.
    void clearLocalAfterBackup(const std::filesystem::path &archive, const std::wstring &password,
                              const std::function<bool()> &canceled = {});
    // Removes only this host's cloud association/profile after explicit consent.
    // The backup must match the opened snapshot; other clients may have advanced
    // the remote head since export. No remote writes or local-vault revival.
    void detachCloudAfterBackup(const std::filesystem::path &archive, const std::wstring &password,
                               const std::function<bool()> &canceled = {});
    void initializeCloud(const std::string &nameSpace, const std::wstring &password);
    void selectCloud(const std::string &nameSpace, const std::wstring &password);
    void migrateCloud(const std::wstring &password);
    void resume(const std::wstring &password);
private:
    struct State;
    std::unique_ptr<State> state;
    std::unique_ptr<Vault> opened;
    void attach();
    void prepareLocal();
    void finishCloud();
    void finishDetach();
};
}
