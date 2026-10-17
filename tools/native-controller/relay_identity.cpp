#include "relay_tls.h"
#include <mbedtls/asn1.h>
#include <mbedtls/ecp.h>
#include <mbedtls/x509_crt.h>
#include <cstring>
#include <stdexcept>

namespace relay {
namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Secret { Bytes bytes; ~Secret() { if (!bytes.empty()) secureZero(bytes.data(), bytes.size()); } };
struct Pk {
    mbedtls_pk_context value;
    Pk() { mbedtls_pk_init(&value); }
    ~Pk() { mbedtls_pk_free(&value); }
    void setup() { tlsCheck(mbedtls_pk_setup(&value, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), "TLS key setup"); }
};
// Only the issuer's private scalar is needed to sign; it never leaves memory.
void loadController(Pk &pk, const Key &controller) {
    Secret blob{controller.blob()}; pk.setup();
    tlsCheck(mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk.value), blob.bytes.data() + 72, 32), "controller key");
}
}
Identity::~Identity() { if (!privateKey.empty()) secureZero(privateKey.data(), privateKey.size()); }
Identity Identity::issue(const Key &controller) {
    Pk issuer, subject; loadController(issuer, controller); subject.setup();
    tlsCheck(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(subject.value), tlsRandom, nullptr), "TLS key generation");
    mbedtls_x509write_cert crt; mbedtls_x509write_crt_init(&crt);
    struct Free { mbedtls_x509write_cert *p; ~Free() { mbedtls_x509write_crt_free(p); } } free{&crt};
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &subject.value); mbedtls_x509write_crt_set_issuer_key(&crt, &issuer.value);
    auto serial = randomBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
    tlsCheck(mbedtls_x509write_crt_set_serial_raw(&crt, serial.data(), serial.size()), "certificate serial");
    auto id = controller.id();
    tlsCheck(mbedtls_x509write_crt_set_subject_name(&crt, "CN=pico-fido2 safe end"), "certificate subject");
    tlsCheck(mbedtls_x509write_crt_set_issuer_name(&crt, ("CN=pico-fido2 controller " + hex(id.data(), id.size())).c_str()), "certificate issuer");
    // Devices check only the controller signature (no clock), so dates are nominal.
    tlsCheck(mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20991231235959"), "certificate validity");
    tlsCheck(mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE), "certificate usage");
    Bytes buffer(1024); int n = mbedtls_x509write_crt_der(&crt, buffer.data(), buffer.size(), tlsRandom, nullptr);
    tlsCheck(n, "certificate encoding");
    Identity out; out.certificate.assign(buffer.end() - n, buffer.end());
    Secret key{Bytes(512)}; n = mbedtls_pk_write_key_der(&subject.value, key.bytes.data(), key.bytes.size());
    tlsCheck(n, "TLS key encoding"); out.privateKey.assign(key.bytes.end() - n, key.bytes.end());
    return out;
}
bool issuedBy(const mbedtls_x509_crt &certificate, const Bytes &controllerPublicKey) {
    if (certificate.next || certificate.MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
        certificate.MBEDTLS_PRIVATE(sig_pk) != MBEDTLS_PK_ECDSA || !crypto::validP256(controllerPublicKey)) return false;
    // DER ECDSA-Sig-Value to raw r||s, as the device does.
    const auto &sig = certificate.MBEDTLS_PRIVATE(sig);
    unsigned char *p = sig.p, *end = sig.p + sig.len; size_t n = 0;
    mbedtls_mpi r, s; mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    Bytes raw(64);
    bool ok = !mbedtls_asn1_get_tag(&p, end, &n, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) && p + n == end &&
        !mbedtls_asn1_get_mpi(&p, end, &r) && !mbedtls_asn1_get_mpi(&p, end, &s) && p == end &&
        !mbedtls_mpi_write_binary(&r, raw.data(), 32) && !mbedtls_mpi_write_binary(&s, raw.data() + 32, 32);
    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    return ok && crypto::verifyP256(controllerPublicKey, hash(Bytes(certificate.tbs.p, certificate.tbs.p + certificate.tbs.len)), raw);
}
}
