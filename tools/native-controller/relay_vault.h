#pragma once
#include "core.h"
#include "relay_cloud.h"
#include "relay_attestation.h"
#include <functional>
#include <mutex>
#include <map>

namespace relay {
struct Account {
    Bytes credentialId, userId;
    std::string rp, userName, displayName;
    bool discoverable = false;
    uint32_t counter = 0;
};
struct Credential : Account {
    Bytes privateKey;
    Credential() = default;
    Credential(const Credential &) = default;
    Credential(Credential &&) noexcept = default;
    Credential &operator=(Credential other) noexcept;
    ~Credential();
};
struct PinRecord {
    Bytes salt, verifier; // PBKDF2-SHA256 of CTAP's 16-byte PIN hash; never the PIN.
    uint8_t retries = 8;
    PinRecord() = default;
    PinRecord(const PinRecord &) = default;
    PinRecord(PinRecord &&) noexcept = default;
    PinRecord &operator=(PinRecord other) noexcept;
    ~PinRecord();
};

// Exactly one backend per lifetime. Local vaults hold an exclusive OS file lock;
// cloud vaults acquire a fresh snapshot/lease per transaction. Neither falls back.
class Vault {
public:
    static constexpr size_t capacity = 4096;
    static std::filesystem::path defaultPath();
    static void create(const std::filesystem::path &path = defaultPath());
    // Explicit offline recovery only: never merge with or replace an initialized vault.
    static void restoreBackup(const std::filesystem::path &backup, const std::wstring &password,
                              const std::filesystem::path &destination = defaultPath());
    explicit Vault(const std::filesystem::path &path = defaultPath());
    // Namespace is the vault's random 128-bit identity encoded in lower-case hex.
    // Opening validates a snapshot, then releases the distributed lease.
    static std::unique_ptr<Vault> openCloud(const std::string &nameSpace, const std::wstring &password,
                                          const CloudLaunch &launch = {});
    static std::unique_ptr<Vault> createCloud(const std::string &nameSpace, const std::wstring &password,
                                            const CloudLaunch &launch = {});
    ~Vault();
    Vault(const Vault &) = delete;
    Vault &operator=(const Vault &) = delete;
    std::vector<Account> accounts() const; // safe-end management only
    // Last authenticated snapshot, only for the unlocked management display.
    // Never use this snapshot to authorize an operation or export credentials.
    std::vector<Account> displayAccounts() const;
    bool contains(const std::string &rp, const std::string &exactUserName) const;
    bool resetDevicePin(std::string serial); // Local safe-end recovery; preserves all credentials.
    void exportBackup(const std::filesystem::path &destination, const std::wstring &password);
    uint64_t revision() const { std::lock_guard<std::mutex> guard(transactionMutex); return generation; }
    bool healthy() const { std::lock_guard<std::mutex> guard(transactionMutex); return !faulted; }
    std::string namespaceId() const;
private:
    friend class Authenticator;
    friend class PinManager;
    friend class Storage;
    explicit Vault(const std::filesystem::path &path, bool allowRetired);
    void retireLocal();
    // Storage holds the backend lock throughout removal and interrupted-clear recovery.
    void clearLocalAfterBackup(const std::filesystem::path &backup, const std::wstring &password,
                              const std::function<bool()> &canceled);
    void verifyBackupForDetach(const std::filesystem::path &backup, const std::wstring &password);
    static void recoverLocalClear(const std::filesystem::path &path);
    static std::unique_ptr<Vault> seedCloud(const std::string &nameSpace, const std::wstring &password,
                                          const CloudLaunch &launch, Vault *source, bool resume, const Bytes &creationToken = {});
    std::function<void()> backendCheck;
    bool retired = false;
    struct CloudState;
    struct CloudTag {};
    explicit Vault(CloudTag);
    std::unique_ptr<CloudState> cloud;
    std::filesystem::path path;
    platform::FileLock lock;
    Id identity{};
    Bytes savedDigest;
    uint64_t generation = 0;
    mutable bool faulted = false;
    mutable std::mutex transactionMutex;
    std::vector<Credential> records;
    std::map<std::string, PinRecord> pins;
    Attestation attestation;
    void check() const;
    // Caller holds transactionMutex. No cloud lease survives a command or a
    // user approval; each acquisition replaces the cache with authoritative data.
    void beginTransaction();
    void endTransaction() noexcept;
    struct Transaction {
        Vault &vault;
        explicit Transaction(Vault &v) : vault(v) { vault.beginTransaction(); }
        ~Transaction() { vault.endTransaction(); }
    };
    void cancellation(std::function<bool()> canceled);
    void checkDisk();
    void commit(std::vector<Credential> next);
    void commit(std::vector<Credential> next, Attestation nextAttestation);
    void commitPins(std::map<std::string, PinRecord> next);
    void commitAll(std::vector<Credential> next, std::map<std::string, PinRecord> nextPins, Attestation nextAttestation);
};
}
