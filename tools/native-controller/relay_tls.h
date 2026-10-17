#pragma once
#include "core.h"
#include <chrono>
#include <functional>
#include <ctime>
#include <memory>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

namespace relay {
using Deadline = std::chrono::steady_clock::time_point;
using Canceled = std::function<bool()>;
void tlsCheck(int code, const char *operation);
int tlsRandom(void *, unsigned char *out, size_t length);
// TLS credentials for one service run: a fresh P-256 key whose certificate is
// signed by the controller key. A device trusts it only if it has paired that
// controller key, so there is no CA, host name or certificate lifetime to manage.
struct Identity {
    Bytes certificate, privateKey; // DER
    Identity() = default;
    Identity(const Identity &) = delete;
    Identity(Identity &&) noexcept = default;
    ~Identity();
    static Identity issue(const Key &controller);
};
// The device-side check: the certificate carries an ECDSA P-256/SHA-256
// signature by this controller public key (0x04 || X || Y).
bool issuedBy(const mbedtls_x509_crt &certificate, const Bytes &controllerPublicKey);
struct Socket {
    using Native = intptr_t; // SOCKET on Windows, file descriptor elsewhere
    static constexpr Native invalid = -1;
    Native handle = invalid;
    Socket() = default;
    explicit Socket(Native socket);
    ~Socket();
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    Socket(Socket &&other) noexcept;
    static Socket listen(const std::string &address, uint16_t port);
    static Socket connect(const std::string &address, uint16_t port, Deadline deadline, const Canceled &cancel);
    Socket accept(Deadline deadline, const Canceled &cancel);
    uint16_t port() const;
    bool wait(bool writing, Deadline deadline, const Canceled &cancel, unsigned interval = 100) const;
    void read(void *out, size_t length, Deadline deadline, const Canceled &cancel);
    void write(const void *data, size_t length, Deadline deadline, const Canceled &cancel);
};
// Owns SSL state, not the socket. One thread at a time may call this object.
class Tls {
public:
    Tls(Socket &socket, const Identity &identity); // server
    Tls(Socket &socket, const Bytes &controllerPublicKey); // client: server must be issued by this key
    ~Tls();
    Tls(const Tls &) = delete;
    Tls &operator=(const Tls &) = delete;
    void handshake(Deadline deadline, const Canceled &cancel);
    void read(void *out, size_t length, Deadline deadline, const Canceled &cancel);
    void write(const void *data, size_t length, Deadline deadline, const Canceled &cancel);
    // Nonblocking receive; zero means no application data, not EOF. EOF throws.
    size_t poll(void *out, size_t capacity);
private:
    Socket &socket;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt certificates;
    mbedtls_pk_context key;
    Bytes issuer; // client only
    bool server, ready = false;
    void init(bool server);
    void cleanup();
};
}
