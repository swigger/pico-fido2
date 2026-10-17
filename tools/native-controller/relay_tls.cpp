#include "relay_tls.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketLength = int;
#else
#include <arpa/inet.h>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketLength = socklen_t;
#endif
#include <cstring>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <algorithm>
#include <mutex>
#include <stdexcept>

namespace relay {
namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void live(Deadline deadline, const Canceled &cancel) {
    require(!cancel || !cancel(), "连接已取消");
    require(std::chrono::steady_clock::now() < deadline, "连接超时");
}
#ifdef _WIN32
using Native = SOCKET;
void initialize() {
    static std::once_flag once; std::call_once(once, [] { WSADATA data{}; require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "无法启动 Windows 网络"); });
}
bool wouldBlock() { auto e = WSAGetLastError(); return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
void closeNative(Socket::Native s) { closesocket(static_cast<SOCKET>(s)); }
constexpr int sendFlags = 0;
#else
using Native = int;
void initialize() {}
bool wouldBlock() { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EINTR; }
void closeNative(Socket::Native s) { ::close(static_cast<int>(s)); }
#ifdef MSG_NOSIGNAL
constexpr int sendFlags = MSG_NOSIGNAL;
#else
constexpr int sendFlags = 0;
#endif
#endif
Native native(Socket::Native s) { return static_cast<Native>(s); }
int sendSome(Socket::Native s, const void *p, size_t n) {
    return static_cast<int>(::send(native(s), static_cast<const char *>(p), static_cast<int>(std::min<size_t>(n, INT_MAX)), sendFlags));
}
int receiveSome(Socket::Native s, void *p, size_t n) {
    return static_cast<int>(::recv(native(s), static_cast<char *>(p), static_cast<int>(std::min<size_t>(n, INT_MAX)), 0));
}
int sendTls(void *p, const unsigned char *buffer, size_t length) {
    int n = sendSome(static_cast<Socket *>(p)->handle, buffer, length);
    if (n >= 0) return n;
    return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}
int receiveTls(void *p, unsigned char *buffer, size_t length) {
    int n = receiveSome(static_cast<Socket *>(p)->handle, buffer, length);
    if (n >= 0) return n;
    return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}
sockaddr_storage numericAddress(const std::string &host, uint16_t port, SocketLength &length) {
    sockaddr_storage addr{};
    auto *v4 = reinterpret_cast<sockaddr_in *>(&addr); auto *v6 = reinterpret_cast<sockaddr_in6 *>(&addr);
    if (inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons(port); length = sizeof(*v4);
    } else if (inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(port); length = sizeof(*v6);
    } else throw std::runtime_error("监听／测试连接地址必须是 IPv4 或 IPv6 字面值");
    return addr;
}
Socket::Native wrap(Native s) {
#ifdef _WIN32
    return s == INVALID_SOCKET ? Socket::invalid : static_cast<Socket::Native>(s);
#else
    return s;
#endif
}
}
void tlsCheck(int code, const char *operation) {
    if (code < 0) { char error[180]{}; mbedtls_strerror(code, error, sizeof(error)); throw std::runtime_error(std::string(operation) + ": " + error); }
}
int tlsRandom(void *p, unsigned char *out, size_t length) {
    return crypto::mbedtlsRandom(p, out, length) ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : 0;
}
Socket::Socket(Native value) : handle(value) {
    require(handle != invalid, "网络套接字失败");
#ifdef _WIN32
    u_long nonblocking = 1; bool ok = !ioctlsocket(native(handle), FIONBIO, &nonblocking);
#else
    int flags = fcntl(native(handle), F_GETFL, 0);
    bool ok = flags >= 0 && fcntl(native(handle), F_SETFL, flags | O_NONBLOCK) == 0 && fcntl(native(handle), F_SETFD, FD_CLOEXEC) == 0;
#ifdef SO_NOSIGPIPE
    int one = 1; setsockopt(native(handle), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#endif
    if (!ok) { closeNative(handle); handle = invalid; throw std::runtime_error("无法启用非阻塞网络"); }
    // TLS handshakes and relay frames contain consecutive short records. Do
    // not wait for a delayed ACK before sending the next record to the device.
    int noDelay = 1;
    if (setsockopt(native(handle), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&noDelay), sizeof(noDelay))) {
        closeNative(handle); handle = invalid; throw std::runtime_error("无法启用低延迟网络");
    }
}
Socket::~Socket() { if (handle != invalid) closeNative(handle); }
Socket::Socket(Socket &&other) noexcept : handle(other.handle) { other.handle = invalid; }
Socket Socket::listen(const std::string &address, uint16_t port) {
    initialize(); SocketLength length = 0; auto addr = numericAddress(address, port, length);
    Socket listener(wrap(::socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP)));
#ifndef _WIN32
    // Restart after TIME_WAIT; Linux/macOS still refuse a second active listener.
    int reuse = 1; setsockopt(native(listener.handle), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#else
    BOOL exclusive = TRUE;
    require(!setsockopt(native(listener.handle), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&exclusive), sizeof(exclusive)), "无法独占监听地址");
#endif
    require(!bind(native(listener.handle), reinterpret_cast<sockaddr *>(&addr), length) && !::listen(native(listener.handle), 4), "无法监听地址／端口");
    return listener;
}
Socket Socket::connect(const std::string &address, uint16_t port, Deadline deadline, const Canceled &cancel) {
    initialize(); SocketLength length = 0; auto addr = numericAddress(address, port, length);
    Socket result(wrap(::socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP)));
    int n = ::connect(native(result.handle), reinterpret_cast<sockaddr *>(&addr), length);
    require(!n || wouldBlock(), "连接安全端失败");
    while (n && !result.wait(true, deadline, cancel)) {}
    int error = 0; SocketLength size = sizeof(error);
    require(!getsockopt(native(result.handle), SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &size) && !error, "连接安全端失败");
    return result;
}
Socket Socket::accept(Deadline deadline, const Canceled &cancel) {
    while (!wait(false, deadline, cancel)) {}
    return Socket(wrap(::accept(native(handle), nullptr, nullptr)));
}
uint16_t Socket::port() const {
    sockaddr_storage addr{}; SocketLength length = sizeof(addr);
    require(!getsockname(native(handle), reinterpret_cast<sockaddr *>(&addr), &length), "无法读取监听端口");
    return ntohs(addr.ss_family == AF_INET ? reinterpret_cast<sockaddr_in *>(&addr)->sin_port : reinterpret_cast<sockaddr_in6 *>(&addr)->sin6_port);
}
bool Socket::wait(bool writing, Deadline deadline, const Canceled &cancel, unsigned interval) const {
    live(deadline, cancel);
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    auto ms = static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(remaining, interval)));
#ifdef _WIN32
    WSAPOLLFD fd{native(handle), static_cast<SHORT>(writing ? POLLWRNORM : POLLRDNORM), 0};
    int n = WSAPoll(&fd, 1, ms);
    require(n != SOCKET_ERROR, "网络等待失败");
#else
    pollfd fd{native(handle), static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    int n = ::poll(&fd, 1, ms);
    if (n < 0 && errno == EINTR) n = 0;
    require(n >= 0, "网络等待失败");
#endif
    live(deadline, cancel); return n > 0;
}
void Socket::read(void *out, size_t length, Deadline deadline, const Canceled &cancel) {
    auto p = static_cast<char *>(out);
    while (length) {
        live(deadline, cancel); int n = receiveSome(handle, p, length);
        if (n < 0 && wouldBlock()) { wait(false, deadline, cancel); continue; }
        require(n > 0, "连接已断开"); p += n; length -= static_cast<size_t>(n);
    }
}
void Socket::write(const void *data, size_t length, Deadline deadline, const Canceled &cancel) {
    auto p = static_cast<const char *>(data);
    while (length) {
        live(deadline, cancel); int n = sendSome(handle, p, length);
        if (n < 0 && wouldBlock()) { wait(true, deadline, cancel); continue; }
        require(n > 0, "连接写入失败"); p += n; length -= static_cast<size_t>(n);
    }
}
void Tls::init(bool isServer) {
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config); mbedtls_x509_crt_init(&certificates); mbedtls_pk_init(&key);
    tlsCheck(mbedtls_ssl_config_defaults(&config, isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT), "TLS configuration");
    mbedtls_ssl_conf_rng(&config, tlsRandom, nullptr);
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    static const int ciphers[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};
    mbedtls_ssl_conf_ciphersuites(&config, ciphers);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&config, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif
    // The client checks the issuing controller key itself after the handshake.
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
}
Tls::Tls(Socket &s, const Identity &identity) : socket(s), server(true) {
    try {
        init(true);
        tlsCheck(mbedtls_x509_crt_parse_der(&certificates, identity.certificate.data(), identity.certificate.size()), "TLS server certificate");
        tlsCheck(mbedtls_pk_parse_key(&key, identity.privateKey.data(), identity.privateKey.size(), nullptr, 0, tlsRandom, nullptr), "TLS server key");
        tlsCheck(mbedtls_pk_check_pair(&certificates.pk, &key, tlsRandom, nullptr), "TLS key/certificate mismatch");
        tlsCheck(mbedtls_ssl_conf_own_cert(&config, &certificates, &key), "TLS server credentials");
        tlsCheck(mbedtls_ssl_setup(&ssl, &config), "TLS setup");
        mbedtls_ssl_set_bio(&ssl, &socket, sendTls, receiveTls, nullptr);
    } catch (...) { cleanup(); throw; }
}
Tls::Tls(Socket &s, const Bytes &controllerPublicKey) : socket(s), issuer(controllerPublicKey), server(false) {
    try {
        init(false); tlsCheck(mbedtls_ssl_setup(&ssl, &config), "TLS setup");
        mbedtls_ssl_set_bio(&ssl, &socket, sendTls, receiveTls, nullptr);
    } catch (...) { cleanup(); throw; }
}
void Tls::cleanup() { mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config); mbedtls_x509_crt_free(&certificates); mbedtls_pk_free(&key); }
Tls::~Tls() { cleanup(); }
void Tls::handshake(Deadline deadline, const Canceled &cancel) {
    for (;;) {
        live(deadline, cancel); int rc = mbedtls_ssl_handshake(&ssl);
        if (!rc) break;
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) { socket.wait(rc == MBEDTLS_ERR_SSL_WANT_WRITE, deadline, cancel); continue; }
        tlsCheck(rc, "TLS handshake");
    }
    if (!server) {
        auto *peer = mbedtls_ssl_get_peer_cert(&ssl);
        require(peer && issuedBy(*peer, issuer), "TLS 身份验证失败：服务器证书不是由已配对的控制端密钥签发");
    }
    ready = true;
}
size_t Tls::poll(void *out, size_t capacity) {
    require(ready && capacity, "TLS 尚未验证");
    int n = mbedtls_ssl_read(&ssl, static_cast<unsigned char *>(out), capacity);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    tlsCheck(n, "TLS read"); require(n > 0, "TLS 连接已断开"); return static_cast<size_t>(n);
}
void Tls::read(void *out, size_t length, Deadline deadline, const Canceled &cancel) {
    auto p = static_cast<unsigned char *>(out);
    while (length) { live(deadline, cancel); size_t n = poll(p, length); if (!n) { socket.wait(false, deadline, cancel); continue; } p += n; length -= n; }
}
void Tls::write(const void *data, size_t length, Deadline deadline, const Canceled &cancel) {
    require(ready, "TLS 尚未验证"); auto p = static_cast<const unsigned char *>(data);
    while (length) {
        live(deadline, cancel); int n = mbedtls_ssl_write(&ssl, p, length);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { socket.wait(n == MBEDTLS_ERR_SSL_WANT_WRITE, deadline, cancel); continue; }
        tlsCheck(n, "TLS write"); require(n > 0, "TLS 写入失败"); p += n; length -= n;
    }
}
}
