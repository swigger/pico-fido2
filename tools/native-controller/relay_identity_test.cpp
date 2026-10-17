#include "relay_tls.h"
#include "relay_attestation.h"
#include <mbedtls/x509_crt.h>
#include <cstdio>
#include <future>
#include <stdexcept>

namespace {
void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> void rejects(F f) { bool failed = false; try { f(); } catch (...) { failed = true; } check(failed, "untrusted TLS identity accepted"); }
struct Crt {
    mbedtls_x509_crt value;
    explicit Crt(const Bytes &der) { mbedtls_x509_crt_init(&value); relay::tlsCheck(mbedtls_x509_crt_parse_der(&value, der.data(), der.size()), "fixture certificate"); }
    ~Crt() { mbedtls_x509_crt_free(&value); }
};
relay::Deadline soon() { return std::chrono::steady_clock::now() + std::chrono::seconds(5); }
// Real loopback handshake: the client accepts only a server issued by `trusted`.
void handshake(const relay::Identity &identity, const Bytes &trusted) {
    auto listener = relay::Socket::listen("127.0.0.1", 0);
    auto server = std::async(std::launch::async, [&] {
        auto socket = listener.accept(soon(), {}); relay::Tls tls(socket, identity);
        try { tls.handshake(soon(), {}); } catch (...) {}
    });
    auto socket = relay::Socket::connect("127.0.0.1", listener.port(), soon(), {});
    struct Join { std::future<void> &f; ~Join() { f.wait(); } } join{server};
    relay::Tls tls(socket, trusted); tls.handshake(soon(), {});
}
}
int main() {
    try {
        auto attestation = relay::Attestation::generate(); attestation.validate();
        auto mismatched = attestation; mismatched.privateKey = Key::generate()->blob();
        rejects([&] { mismatched.validate(); });
        auto broken = attestation; broken.certificate.back() ^= 1;
        rejects([&] { broken.validate(); });
        auto controller = Key::generate(), other = Key::generate();
        auto identity = relay::Identity::issue(*controller), second = relay::Identity::issue(*controller);
        check(identity.certificate != second.certificate && identity.privateKey != second.privateKey, "TLS key reused across service starts");
        Crt crt(identity.certificate);
        check(relay::issuedBy(crt.value, controller->pub()), "issued certificate rejected");
        check(!relay::issuedBy(crt.value, other->pub()), "certificate accepted for another controller");
        check(!relay::issuedBy(crt.value, Bytes(65, 4)), "invalid controller key accepted");
        // Any change to the signed body breaks the controller signature.
        auto tampered = identity.certificate; tampered[tampered.size() / 2] ^= 1;
        mbedtls_x509_crt bad; mbedtls_x509_crt_init(&bad);
        bool parsed = mbedtls_x509_crt_parse_der(&bad, tampered.data(), tampered.size()) == 0;
        check(!parsed || !relay::issuedBy(bad, controller->pub()), "tampered certificate accepted");
        mbedtls_x509_crt_free(&bad);
        mbedtls_pk_context key; mbedtls_pk_init(&key);
        int rc = mbedtls_pk_parse_key(&key, identity.privateKey.data(), identity.privateKey.size(), nullptr, 0, relay::tlsRandom, nullptr);
        if (!rc) rc = mbedtls_pk_check_pair(&crt.value.pk, &key, relay::tlsRandom, nullptr);
        mbedtls_pk_free(&key); check(rc == 0, "TLS key does not match its certificate");
        handshake(identity, controller->pub());
        rejects([&] { handshake(identity, other->pub()); });
        std::puts("PASS: per-start TLS identity issued by the controller key, signature pinning, tamper and wrong-key rejection");
        return 0;
    } catch (const std::exception &e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
