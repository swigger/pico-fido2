#include "relay_attestation.h"
#include "relay_tls.h"
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <cstring>
#include <stdexcept>

namespace relay {
namespace {
void require(bool ok) { if (!ok) throw std::runtime_error("注册证明密钥或证书无效"); }
struct Pk {
    mbedtls_pk_context value;
    Pk() { mbedtls_pk_init(&value); }
    ~Pk() { mbedtls_pk_free(&value); }
};
}
Attestation::~Attestation() { if (!privateKey.empty()) secureZero(privateKey.data(), privateKey.size()); }
Attestation &Attestation::operator=(Attestation other) noexcept {
    privateKey.swap(other.privateKey); certificate.swap(other.certificate); return *this;
}
Attestation Attestation::generate() {
    Attestation out; auto key = Key::generate(); out.privateKey = key->blob();
    Pk pk;
    tlsCheck(mbedtls_pk_setup(&pk.value, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), "attestation key setup");
    auto ec = mbedtls_pk_ec(pk.value);
    tlsCheck(mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, ec, out.privateKey.data() + 72, 32), "attestation key");
    auto pub = key->pub();
    tlsCheck(mbedtls_ecp_point_read_binary(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q), pub.data(), pub.size()), "attestation public key");
    mbedtls_x509write_cert crt; mbedtls_x509write_crt_init(&crt);
    struct Free { mbedtls_x509write_cert *p; ~Free() { mbedtls_x509write_crt_free(p); } } free{&crt};
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk.value);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk.value);
    auto serial = randomBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
    tlsCheck(mbedtls_x509write_crt_set_serial_raw(&crt, serial.data(), serial.size()), "attestation serial");
    // Locally issued project certificate, as in standalone mode; not FIDO certification.
    const char *name = "C=ES,O=Pico HSM,OU=Authenticator Attestation,CN=Pico FIDO2 relay";
    tlsCheck(mbedtls_x509write_crt_set_subject_name(&crt, name), "attestation subject");
    tlsCheck(mbedtls_x509write_crt_set_issuer_name(&crt, name), "attestation issuer");
    tlsCheck(mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20991231235959"), "attestation validity");
    tlsCheck(mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1), "attestation constraints");
    tlsCheck(mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE), "attestation usage");
    Bytes buffer(2048);
    int n = mbedtls_x509write_crt_der(&crt, buffer.data(), buffer.size(), tlsRandom, nullptr);
    tlsCheck(n, "attestation certificate"); out.certificate.assign(buffer.end() - n, buffer.end());
    out.validate(); return out;
}
void Attestation::validate() const {
    if (privateKey.empty() && certificate.empty()) return;
    require(privateKey.size() == 104 && !certificate.empty() && certificate.size() <= 2048);
    auto key = Key::fromBlob(privateKey);
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    struct Free { mbedtls_x509_crt *p; ~Free() { mbedtls_x509_crt_free(p); } } free{&crt};
    require(mbedtls_x509_crt_parse_der(&crt, certificate.data(), certificate.size()) == 0);
    require(!crt.next && crt.raw.len == certificate.size() && crt.version == 3 && !crt.MBEDTLS_PRIVATE(ca_istrue) &&
        (crt.MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) &&
        (crt.MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_KEY_USAGE) && crt.MBEDTLS_PRIVATE(key_usage) == MBEDTLS_X509_KU_DIGITAL_SIGNATURE &&
        crt.MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA256 && mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_ECDSA));
    bool ou = false;
    for (auto name = &crt.subject; name; name = name->next)
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_ORG_UNIT, &name->oid) == 0)
            ou = name->val.len == 25 && !memcmp(name->val.p, "Authenticator Attestation", 25);
    require(ou && crt.subject_raw.len == crt.issuer_raw.len &&
        !memcmp(crt.subject_raw.p, crt.issuer_raw.p, crt.subject_raw.len));
    auto ec = mbedtls_pk_ec(crt.pk); Bytes pub(65); size_t n = 0;
    require(ec->MBEDTLS_PRIVATE(grp).id == MBEDTLS_ECP_DP_SECP256R1 &&
        mbedtls_ecp_point_write_binary(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
            &n, pub.data(), pub.size()) == 0 && n == pub.size() && pub == key->pub());
    auto digest = hash(Bytes(crt.tbs.p, crt.tbs.p + crt.tbs.len));
    require(mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, digest.data(), digest.size(),
        crt.MBEDTLS_PRIVATE(sig).p, crt.MBEDTLS_PRIVATE(sig).len) == 0);
}
}
