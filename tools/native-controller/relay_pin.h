#pragma once
#include "credentials.h"
#include "relay_vault.h"
#include <chrono>
#include <memory>

namespace relay {
struct Operation;
namespace pin {
Bytes shared(unsigned protocol, const ctap::Agreement &own, const ctap::Value &peer);
Bytes encrypt(unsigned protocol, const Bytes &shared, const Bytes &plain);
Bytes decrypt(unsigned protocol, const Bytes &shared, const Bytes &cipher);
Bytes authenticate(unsigned protocol, const Bytes &key, const Bytes &message);
bool equal(const Bytes &a, const Bytes &b);
}
// Called only while the owning vault's transaction mutex is held. PIN records
// persist in the same commit as credentials; tokens/key agreement remain volatile.
class PinManager {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;
    using Consent = std::function<void(uint8_t subcommand, unsigned permissions, const std::string &rp)>;
    explicit PinManager(Vault &vault, Clock clock = {});
    ~PinManager();
    bool configured(const std::string &serial) const;
    Bytes exchange(const ctap::Value &params, const Operation &op, const Consent &consent);
    // Return a non-secret identity for this token. Only an approved assertion
    // preflight (including a negative exclude-list result) may defer consumption
    // until a user-present request. This alone never grants approval.
    Bytes verify(const Operation &op, unsigned protocol, const Bytes &auth, const Bytes &clientHash,
                 const std::string &rp, unsigned permission, bool consume = true);
    void invalidate(const Operation &op);
private:
    struct State;
    Vault &vault;
    std::unique_ptr<State> state;
};
}
