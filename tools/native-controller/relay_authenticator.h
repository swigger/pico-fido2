#pragma once
#include "relay_vault.h"
#include "relay_pin.h"
#include <chrono>
#include <mutex>

namespace relay {
struct Approval {
    uint8_t operation = 0;
    uint8_t pinSubcommand = 0;
    unsigned pinPermissions = 0;
    unsigned batchWindowSeconds = 0; // Negative queries only; no account/registration consent.
    std::string deviceSerial, rp, queryUserName;
    Id requestId{};
    Bytes requestHash;
    std::vector<Account> accounts; // only candidates for this RP/request
};
struct Decision {
    bool allow = false;
    Bytes credentialId; // assertion: explicitly select exactly one candidate
};
struct Operation {
    // Set by the authenticated transport, never accepted as proof of identity.
    std::string deviceSerial;
    Id requestId{};
    Id bootId{}, enrollmentId{}; // authenticated device boot and enrollment scope
    std::chrono::steady_clock::time_point deadline;
    std::function<bool()> canceled;
};
class Authenticator {
public:
    using Approve = std::function<Decision(const Approval &, const Operation &)>;
    Authenticator(Vault &vault, Approve approve, PinManager::Clock clock = {})
        : vault(vault), approve(std::move(approve)),
          clock(clock ? std::move(clock) : PinManager::Clock([] { return std::chrono::steady_clock::now(); })),
          pins(vault, this->clock) {}
    // A CTAP status byte followed by optional canonical CBOR. Serializes calls;
    // concurrent requests receive CHANNEL_BUSY rather than sharing an approval.
    Bytes exchange(const Bytes &request, const Operation &operation);
    // Public hints from the last validated snapshot; never acquires a cloud lock.
    Bytes discovery(const std::string &serial);
    // A failed/canceled response must not leave an undelivered preflight grant.
    void cancel(const Operation &operation);
private:
    Vault &vault;
    Approve approve;
    PinManager::Clock clock;
    PinManager pins;
    struct AssertionGrant {
        Id boot{}, enrollment{}, requestId{};
        Bytes token, scope, keyHash;
        Account account;
        Bytes batchScope;
        std::chrono::steady_clock::time_point batchDeadline{};
    };
    // At most one grant per PIN session (PinManager bounds sessions to 256).
    // Negative batches share a fixed short window and a request fingerprint
    // excluding allowList. They never carry an account/formal assertion grant.
    // No private keys, transport callbacks or cloud leases survive here.
    std::map<std::string, AssertionGrant> assertionGrants;
    Bytes perform(const Bytes &request, const Operation &operation);
};
}
