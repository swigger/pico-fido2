#include "crypto.h"
#include <cstring>
#include <stdexcept>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#endif

namespace crypto {
namespace {
constexpr uint32_t privateMagic = 0x32534345; // "ECS2", BCRYPT_ECDSA_PRIVATE_P256_MAGIC
void check(int rc, const char *message) { if (rc != 0) throw std::runtime_error(message); }
struct Mpi {
    mbedtls_mpi v;
    Mpi() { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
};
void put32(unsigned char *p, uint32_t n) { for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<unsigned char>(n >> (8 * i)); }
uint32_t get32(const unsigned char *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
}
int mbedtlsRandom(void *, unsigned char *out, size_t length) {
    try { platform::randomFill(out, length); return 0; }
    catch (...) { return MBEDTLS_ERR_ECP_RANDOM_FAILED; }
}
Bytes randomBytes(size_t n) { Bytes b(n); if (n) platform::randomFill(b.data(), n); return b; }
Bytes sha256(const Bytes &data) {
    Bytes out(32); check(mbedtls_sha256(data.data(), data.size(), out.data(), 0), "SHA-256 失败"); return out;
}
Bytes hmacSha256(const Bytes &key, const Bytes &message) {
    Bytes out(32);
    check(mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key.data(), key.size(), message.data(),
        message.size(), out.data()), "HMAC 失败");
    return out;
}
Bytes pbkdf2Sha256(const unsigned char *password, size_t passwordLength, const unsigned char *salt, size_t saltLength,
                   unsigned iterations, size_t outputLength) {
    Bytes out(outputLength);
    // 600k iterations protect PINs and backups; use the OS implementation (SHA
    // extensions) where present, it is several times faster than portable code.
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0;
    if (ok) ok = BCryptDeriveKeyPBKDF2(algorithm, const_cast<PUCHAR>(password), static_cast<ULONG>(passwordLength),
        const_cast<PUCHAR>(salt), static_cast<ULONG>(saltLength), iterations, out.data(), static_cast<ULONG>(outputLength), 0) >= 0;
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) throw std::runtime_error("密码派生失败");
    return out;
#elif defined(__APPLE__)
    check(CCKeyDerivationPBKDF(kCCPBKDF2, reinterpret_cast<const char *>(password), passwordLength, salt, saltLength,
        kCCPRFHmacAlgSHA256, iterations, out.data(), outputLength) == kCCSuccess ? 0 : -1, "密码派生失败");
    return out;
#else
    check(mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password, passwordLength, salt, saltLength, iterations,
        static_cast<uint32_t>(outputLength), out.data()), "密码派生失败");
    return out;
#endif
}
Bytes gcmEncrypt(const Bytes &key, const unsigned char *nonce, const Bytes &aad, const unsigned char *plain, size_t length,
                 unsigned char tag[16]) {
    if (key.size() != 32) throw std::runtime_error("AES 密钥长度不正确");
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    Bytes out(length);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (!rc) rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, length, nonce, 12, aad.data(), aad.size(),
        plain, out.data(), 16, tag);
    mbedtls_gcm_free(&gcm);
    if (rc) { wipe(out); throw std::runtime_error("AES-GCM 加密失败"); }
    return out;
}
Bytes gcmDecrypt(const Bytes &key, const unsigned char *nonce, const Bytes &aad, const unsigned char *cipher, size_t length,
                 const unsigned char tag[16], const char *error) {
    if (key.size() != 32) throw std::runtime_error(error);
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    Bytes out(length);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (!rc) rc = mbedtls_gcm_auth_decrypt(&gcm, length, nonce, 12, aad.data(), aad.size(), tag, 16, cipher, out.data());
    mbedtls_gcm_free(&gcm);
    if (rc) {
        wipe(out);
        if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) throw AuthenticationError(error);
        throw std::runtime_error(error);
    }
    return out;
}
Bytes aesCbc(const Bytes &key, const Bytes &iv, const Bytes &input, bool encrypt) {
    if (key.size() != 32 || iv.size() != 16 || input.empty() || input.size() % 16)
        throw std::runtime_error("安全密钥返回了无效的数据");
    mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    unsigned char chain[16]; std::memcpy(chain, iv.data(), 16);
    Bytes out(input.size());
    int rc = encrypt ? mbedtls_aes_setkey_enc(&aes, key.data(), 256) : mbedtls_aes_setkey_dec(&aes, key.data(), 256);
    if (!rc) rc = mbedtls_aes_crypt_cbc(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, input.size(), chain,
        input.data(), out.data());
    mbedtls_aes_free(&aes);
    if (rc) { wipe(out); throw std::runtime_error("PIN 加密通信失败"); }
    return out;
}

struct P256::State {
    mbedtls_ecp_keypair key;
    State() { mbedtls_ecp_keypair_init(&key); }
    ~State() { mbedtls_ecp_keypair_free(&key); }
};
P256::P256() : state(std::make_unique<State>()) {}
P256::~P256() = default;
std::unique_ptr<P256> P256::generate() {
    auto k = std::make_unique<P256>();
    check(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &k->state->key, mbedtlsRandom, nullptr), "生成密钥失败");
    return k;
}
std::unique_ptr<P256> P256::fromBlob(const Bytes &b) {
    if (b.size() != 104 || get32(b.data()) != privateMagic || get32(b.data() + 4) != 32)
        throw std::runtime_error("密钥格式不正确");
    auto k = std::make_unique<P256>();
    auto &key = k->state->key;
    check(mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, b.data() + 72, 32), "私钥校验失败");
    Bytes point(65); point[0] = 4; std::memcpy(point.data() + 1, b.data() + 8, 64);
    mbedtls_ecp_keypair pub; mbedtls_ecp_keypair_init(&pub);
    int rc = mbedtls_ecp_group_load(&pub.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc = mbedtls_ecp_point_read_binary(&pub.MBEDTLS_PRIVATE(grp), &pub.MBEDTLS_PRIVATE(Q), point.data(), point.size());
    // Recompute Q = d·G for the private key, then require it to equal the stored half.
    if (!rc) rc = mbedtls_ecp_keypair_calc_public(&key, mbedtlsRandom, nullptr);
    if (!rc) rc = mbedtls_ecp_check_pub_priv(&pub, &key, mbedtlsRandom, nullptr);
    mbedtls_ecp_keypair_free(&pub);
    check(rc, "公钥与私钥不匹配");
    return k;
}
Bytes P256::publicKey() const {
    auto &key = state->key;
    if (mbedtls_ecp_is_zero(&key.MBEDTLS_PRIVATE(Q)))
        check(mbedtls_ecp_mul(&key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q), &key.MBEDTLS_PRIVATE(d),
            &key.MBEDTLS_PRIVATE(grp).G, mbedtlsRandom, nullptr), "读取公钥失败");
    Bytes out(65); size_t n = 0;
    check(mbedtls_ecp_point_write_binary(&key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
        &n, out.data(), out.size()), "读取公钥失败");
    if (n != 65) throw std::runtime_error("公钥格式不正确");
    return out;
}
Bytes P256::blob() const {
    auto pub = publicKey();
    Bytes out(104); put32(out.data(), privateMagic); put32(out.data() + 4, 32);
    std::memcpy(out.data() + 8, pub.data() + 1, 64);
    check(mbedtls_mpi_write_binary(&state->key.MBEDTLS_PRIVATE(d), out.data() + 72, 32), "导出密钥失败");
    return out;
}
Bytes P256::signDigest(const Bytes &digest) const {
    if (digest.size() != 32) throw std::runtime_error("签名摘要长度错误");
    Mpi r, s; auto &key = state->key;
    check(mbedtls_ecdsa_sign(&key.MBEDTLS_PRIVATE(grp), &r.v, &s.v, &key.MBEDTLS_PRIVATE(d), digest.data(), 32,
        mbedtlsRandom, nullptr), "签名失败");
    Bytes sig(64);
    check(mbedtls_mpi_write_binary(&r.v, sig.data(), 32) | mbedtls_mpi_write_binary(&s.v, sig.data() + 32, 32), "签名失败");
    return sig;
}
Bytes P256::sign(const Bytes &message) const { return signDigest(sha256(message)); }
Bytes P256::agree(const Bytes &x, const Bytes &y) const {
    if (x.size() != 32 || y.size() != 32) throw std::runtime_error("安全密钥返回了无效的数据");
    auto &key = state->key;
    mbedtls_ecp_point peer, shared; mbedtls_ecp_point_init(&peer); mbedtls_ecp_point_init(&shared);
    Bytes point(65); point[0] = 4; std::memcpy(point.data() + 1, x.data(), 32); std::memcpy(point.data() + 33, y.data(), 32);
    int rc = mbedtls_ecp_point_read_binary(&key.MBEDTLS_PRIVATE(grp), &peer, point.data(), point.size());
    if (!rc) rc = mbedtls_ecp_check_pubkey(&key.MBEDTLS_PRIVATE(grp), &peer);
    if (!rc) rc = mbedtls_ecp_mul(&key.MBEDTLS_PRIVATE(grp), &shared, &key.MBEDTLS_PRIVATE(d), &peer, mbedtlsRandom, nullptr);
    Bytes out(32);
    if (!rc) rc = mbedtls_mpi_write_binary(&shared.MBEDTLS_PRIVATE(X), out.data(), 32);
    mbedtls_ecp_point_free(&peer); mbedtls_ecp_point_free(&shared);
    if (rc) { wipe(out); throw std::runtime_error("PIN 密钥协商失败"); }
    return out;
}
bool validP256(const Bytes &publicKey) {
    if (publicKey.size() != 65 || publicKey[0] != 4) return false;
    mbedtls_ecp_group group; mbedtls_ecp_point q; mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&q);
    int rc = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc = mbedtls_ecp_point_read_binary(&group, &q, publicKey.data(), publicKey.size());
    if (!rc) rc = mbedtls_ecp_check_pubkey(&group, &q);
    mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&group);
    return rc == 0;
}
bool verifyP256(const Bytes &publicKey, const Bytes &digest, const Bytes &signature) {
    if (publicKey.size() != 65 || digest.size() != 32 || signature.size() != 64) return false;
    mbedtls_ecp_group group; mbedtls_ecp_point q; mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&q);
    Mpi r, s;
    int rc = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc = mbedtls_ecp_point_read_binary(&group, &q, publicKey.data(), publicKey.size());
    if (!rc) rc = mbedtls_mpi_read_binary(&r.v, signature.data(), 32);
    if (!rc) rc = mbedtls_mpi_read_binary(&s.v, signature.data() + 32, 32);
    if (!rc) rc = mbedtls_ecdsa_verify(&group, digest.data(), 32, &q, &r.v, &s.v);
    mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&group);
    return rc == 0;
}
}
