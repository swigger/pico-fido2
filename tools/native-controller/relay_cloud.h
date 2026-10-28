#pragma once
#include "core.h"
#include <chrono>
#include <functional>
#include <stdexcept>

namespace relay {
// Production uses the helper beside the application and its protected default
// profile. Explicit paths support isolated integration fixtures and packaging.
struct CloudLaunch {
    std::filesystem::path helper, profile;
    std::chrono::milliseconds timeout{60000};
    std::function<bool()> canceled;
    // Optional per-namespace record of the newest vault generation seen on this
    // host. A cloud head older than it (restored coordinator, rewritten head) is refused.
    std::filesystem::path highWater;
};
struct CloudSnapshot { uint64_t generation = 0; Bytes encrypted; };
struct EnrollmentQuestion {
    uint8_t kind = 0; // 1 browser, 3 provider question, 4 explicit save review.
    std::string name, message, value;
    bool required = false, exclusive = false, secret = false;
    std::vector<std::pair<std::string, std::string>> choices;
};

struct CloudIntegrityError : std::runtime_error {
    CloudIntegrityError() : std::runtime_error("云端快照后台校验失败，已停止当前凭证库；请重新打开并检查") {}
};

// One owned child, successive short locks, five-minute idle retention.
// Only a clean idle exit can restart automatically, before any new transaction.
// Callers serialize access and authenticate the encrypted vault themselves.
class CloudStorage {
public:
    static Id identity(const std::string &nameSpace);
    // Local configuration presence only; never contacts or initializes the cloud.
    static bool profileConfigured(const std::string &nameSpace, const CloudLaunch &launch = {});
    static std::vector<std::string> configuredNamespaces(const std::filesystem::path &directory);
    // Local OS lock only, compatible with the helper's profile lock. The caller
    // must first stop its helper and durably record explicit detach consent.
    // Idempotent; preserves the non-secret lock marker and all remote data.
    static void forgetProfile(const std::string &nameSpace, const CloudLaunch &launch = {});
    static void saveProfile(const std::string &nameSpace, const Bytes &setupJson, const CloudLaunch &launch = {});
    static void enrollProfile(const std::string &nameSpace, const Bytes &setupJson,
                              const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch = {});
    static void updateProfile(const std::string &nameSpace, const Bytes &patchJson,
                              const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch = {});
    explicit CloudStorage(const std::string &nameSpace, const CloudLaunch &launch = {});
    ~CloudStorage();
    CloudStorage(const CloudStorage &) = delete;
    CloudStorage &operator=(const CloudStorage &) = delete;
    CloudSnapshot open(bool initialize, bool resume = false, const Bytes &creationToken = {});
    // An empty encrypted result means the authoritative head exactly matches
    // this already authenticated generation/digest; a fresh lease is still held.
    CloudSnapshot openCached(uint64_t generation, const Bytes &ciphertextHash);
    void check();
    uint64_t commit(uint64_t expected, const Bytes &encrypted);
    void release();
    void close();
    void cancellation(std::function<bool()> canceled);
private:
    static void profileFlow(const std::string &nameSpace, const Bytes &json,
                            const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch, bool update);
    struct Impl;
    std::unique_ptr<Impl> state;
};
}
