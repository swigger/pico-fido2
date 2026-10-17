#pragma once
#include <stdexcept>
// Portable primitives on Mbed TLS. Formats stay byte-compatible with the earlier
// Windows CNG implementation (P-256 private blobs, raw r||s signatures).
#include "platform.h"
#include <memory>

namespace crypto {
Bytes randomBytes(size_t n);
int mbedtlsRandom(void *, unsigned char *out, size_t length); // f_rng adapter
Bytes sha256(const Bytes &data);
Bytes hmacSha256(const Bytes &key, const Bytes &message);
Bytes pbkdf2Sha256(const unsigned char *password, size_t passwordLength, const unsigned char *salt, size_t saltLength,
                   unsigned iterations, size_t outputLength);
// AES-256-GCM with a 12-byte nonce and 16-byte tag. Decryption throws on any mismatch.
Bytes gcmEncrypt(const Bytes &key, const unsigned char *nonce, const Bytes &aad, const unsigned char *plain, size_t length,
                 unsigned char tag[16]);
struct AuthenticationError : std::runtime_error { using std::runtime_error::runtime_error; };
Bytes gcmDecrypt(const Bytes &key, const unsigned char *nonce, const Bytes &aad, const unsigned char *cipher, size_t length,
                 const unsigned char tag[16], const char *error);
// AES-256-CBC without padding (CTAP ClientPIN).
Bytes aesCbc(const Bytes &key, const Bytes &iv, const Bytes &input, bool encrypt);

// ECDSA/ECDH P-256 key pair. blob() is the 104-byte layout of a Windows
// BCRYPT_ECCPRIVATE_BLOB: magic, length, X, Y, d (little-endian header).
class P256 {
public:
    P256();
    ~P256();
    P256(const P256 &) = delete;
    P256 &operator=(const P256 &) = delete;
    static std::unique_ptr<P256> generate();
    static std::unique_ptr<P256> fromBlob(const Bytes &blob); // validates the pair
    Bytes blob() const;
    Bytes publicKey() const;                       // 0x04 || X || Y
    Bytes sign(const Bytes &message) const;        // SHA-256 then raw r||s
    Bytes signDigest(const Bytes &digest) const;   // raw r||s
    Bytes agree(const Bytes &peerX, const Bytes &peerY) const; // big-endian shared X
private:
    struct State;
    std::unique_ptr<State> state;
};
bool verifyP256(const Bytes &publicKey, const Bytes &digest, const Bytes &signature);
bool validP256(const Bytes &publicKey); // uncompressed point on the curve
}
