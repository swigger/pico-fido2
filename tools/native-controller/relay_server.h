#pragma once
#include "relay_tls.h"
#include "relay_authenticator.h"

namespace relay {
class Server {
public:
    // Returns the trusted public key for a device serial, or empty to refuse it.
    // Called again while a request is pending: a changed answer cancels the work.
    using Authorize = std::function<Bytes(const std::string &)>;
    // Issues fresh TLS credentials signed by `controller`; devices that paired
    // this controller key accept them.
    Server(Vault &vault, const Key &controller, Authorize authorize, Authenticator::Approve approve);
    void session(Socket socket, const Canceled &stop);
    void run(const std::string &bindAddress, uint16_t port, const Canceled &stop,
             const std::function<void(uint16_t)> &ready = {}, const std::function<void(const std::string &)> &error = {},
             const std::function<void()> &betweenSessions = {});
private:
    Identity identity;
    Authorize authorize;
    bool waitingForApproval = false; // Only accessed on the serialized session thread.
    Authenticator authenticator;
};
}
