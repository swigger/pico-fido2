#pragma once
// UI-independent owner of the safe-end storage. One worker thread performs every
// storage/vault/service action so ownership never moves between threads; the UI
// only submits jobs, answers questions and renders published snapshots.
#include "relay_storage.h"
#include "relay_authenticator.h"
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace relay {
struct SessionSnapshot {
    StorageKind kind = StorageKind::Local;
    std::string nameSpace;
    std::vector<std::string> cloudProfiles; // Saved local cloud configurations, not remote vaults.
    std::string status = "正在读取存储设置…"; // UTF-8
    bool initialized = false, unlocked = false;
    std::vector<Account> rows;
    uint64_t version = 0;
};
class SafeEndSession {
public:
    // Local-only question kind; the cloud helper protocol only accepts 1, 3, 4.
    static constexpr uint8_t ClearLocalAfterBackupQuestion = 5;
    static constexpr uint8_t DetachCloudAfterBackupQuestion = 6;
    static constexpr uint8_t CloudRecoveryCodeQuestion = 7;
    // notify() runs on the worker thread whenever state or a question changes.
    SafeEndSession(std::filesystem::path directory, std::function<void()> notify, const CloudLaunch &cloudLaunch = {});
    ~SafeEndSession(); // cancels, stops the worker and releases ownership
    SafeEndSession(const SafeEndSession &) = delete;
    SafeEndSession &operator=(const SafeEndSession &) = delete;

    const std::filesystem::path &directory() const { return dir; }
    SessionSnapshot snapshot() const;
    bool busy() const { return working.load(); }
    // True only while a user-visible job or the relay service owns the worker.
    // The periodic idle ownership/health check keeps working set but is not a
    // user operation and must not flicker the panel.
    bool visibleBusy() const { return working.load() && !maintenance.load(); }
    bool canceled() const { return cancel.load() || closing.load(); }
    // Worker-side retry delay, interrupted immediately by manual stop/close.
    bool waitToRetry(std::chrono::milliseconds delay);
    CloudLaunch launch() const;

    // Accepted while idle or during the quiet ownership/health check; returns
    // false while a user-visible job or the service is running, or when closing.
    bool submit(std::function<void()> action);
    // Cancels the current job (if any), then releases the vault on the worker.
    void requestLock();
    void close();
    // While a long job (the relay service) owns the vault: asks it to publish
    // the account list again at its next opportunity.
    void requestRows() { rowsWanted = true; }
    bool takeRowsRequest() { return rowsWanted.exchange(false); }

    // Worker-side helpers for jobs.
    void publish(const std::string &message, bool rows = false);
    // Replaces the published account list, keeping the status text.
    void publishRows(bool refresh = true);
    void readState();
    void release();
    void acquire(const std::wstring &password);
    // GUI unlock: try the OS-protected code, otherwise ask for code + remember
    // choice. The answer is "0"/"1" followed by the normalized recovery code.
    void acquireRemembered();
    // Export first, then offer optional local removal while retaining ownership.
    void exportBackup(const std::filesystem::path &path, const std::wstring &password);
    Storage &storage();                 // creates the owner if needed
    void resetStorage();                // drops and recreates on next use
    Vault *vault() const { return opened; }
    void setNamespace(const std::string &nameSpace);
    // Blocks the worker until the UI answers; throws when canceled or locked.
    std::string ask(const EnrollmentQuestion &question);

    // UI-side question handshake.
    bool pendingQuestion(EnrollmentQuestion &out);
    void answer(bool accepted, const std::string &value);
    bool done() const { return finished.load(); }
private:
    struct Question {
        EnrollmentQuestion question; std::string answer; bool dispatched = false, complete = false, failed = false;
        ~Question() { wipe(answer); }
    };
    std::filesystem::path dir;
    std::function<void()> notify;
    CloudLaunch cloudLaunch;
    std::unique_ptr<Storage> owner;
    Vault *opened = nullptr;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::function<void()> pending;
    SessionSnapshot state;
    bool lockRequested = false;
    std::shared_ptr<Question> question;
    std::atomic_bool working{false}, cancel{false}, closing{false}, finished{false}, rowsWanted{false};
    std::atomic_bool maintenance{false};
    std::thread worker;
    void run();
};
// Jobs shared by the GUI and tests; each runs on the session worker.
// Keeps the TLS relay service active until canceled, reopening/revalidating the
// vault after failures. A declined recovery-code prompt ends the operation.
void serveRelay(SafeEndSession &session, const std::string &address, uint16_t port, Authenticator::Approve approve,
                const std::function<void(uint16_t)> &ready = {});
// Explicit controller identity also permits isolated service lifecycle tests.
void serveRelay(SafeEndSession &session, const Key &controller, const std::string &address, uint16_t port,
                Authenticator::Approve approve, const std::function<void(uint16_t)> &ready = {},
                std::chrono::milliseconds retryDelay = std::chrono::seconds(5));
}
