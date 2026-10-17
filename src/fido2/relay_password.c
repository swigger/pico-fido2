#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE)
#include "relay_password.h"
#include "pico_random.h"
#include "remote_presence.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include <string.h>

#define NONCE_SIZE 12
#define TAG_SIZE 16
#define RAW_MAX (NONCE_SIZE + RELAY_MAX_PASSWORD_PLAIN + TAG_SIZE)

static const char keyPurpose[] = "pico-fido2 relay password key v1";
static const char aadDomain[] = "pico-fido2 relay password v1";

static bool hex_digit(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static unsigned hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
    return (unsigned)(c - 'A' + 10);
}
static size_t aad(uint8_t *out, const uint8_t serial[16]) {
    size_t n = sizeof(aadDomain) - 1;
    memcpy(out, aadDomain, n);
    memcpy(out + n, serial, 16);
    return n + 16;
}

bool relay_password_seal(const uint8_t serial[16], const char *plain, size_t plain_length,
                         char *token, size_t token_capacity, size_t *token_length) {
    if (token_length) *token_length = 0;
    if (!serial || !plain || !token || !token_length || !plain_length ||
        plain_length > RELAY_MAX_PASSWORD_PLAIN || !relay_config_password_plain(plain, plain_length))
        return false;
    size_t raw_length = NONCE_SIZE + plain_length + TAG_SIZE;
    if (token_capacity < RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * raw_length) return false;
    uint8_t raw[RAW_MAX] = {0};
    uint8_t *nonce = raw, *cipher = raw + NONCE_SIZE, *tag = cipher + plain_length;
    uint8_t key[32] = {0};
    if (!remote_presence_derive_key(keyPurpose, key)) {
        mbedtls_platform_zeroize(raw, sizeof(raw));
        return false;
    }
    picok_random_fill(nonce, NONCE_SIZE);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    uint8_t associated[sizeof(aadDomain) - 1 + 16];
    size_t associated_length = aad(associated, serial);
    int err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!err)
        err = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_length, nonce, NONCE_SIZE,
                                        associated, associated_length, (const uint8_t *)plain, cipher,
                                        TAG_SIZE, tag);
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(associated, sizeof(associated));
    if (err) {
        mbedtls_platform_zeroize(raw, sizeof(raw));
        return false;
    }
    static const char digits[] = "0123456789abcdef";
    memcpy(token, RELAY_PASSWORD_TOKEN_PREFIX, RELAY_PASSWORD_TOKEN_PREFIX_LENGTH);
    for (size_t i = 0; i < raw_length; ++i) {
        token[RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * i] = digits[raw[i] >> 4];
        token[RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * i + 1] = digits[raw[i] & 15];
    }
    *token_length = RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * raw_length;
    mbedtls_platform_zeroize(raw, sizeof(raw));
    return true;
}

bool relay_password_open(const uint8_t serial[16], const char *token, size_t token_length,
                         char *plain, size_t plain_capacity, size_t *plain_length) {
    if (plain_length) *plain_length = 0;
    if (!serial || !token || !plain || !plain_length ||
        !relay_config_password_token(token, token_length)) return false;
    size_t raw_length = (token_length - RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) / 2;
    if (raw_length < NONCE_SIZE + TAG_SIZE || raw_length > RAW_MAX) return false;
    size_t cipher_length = raw_length - NONCE_SIZE - TAG_SIZE;
    if (!cipher_length || cipher_length > plain_capacity || cipher_length > RELAY_MAX_PASSWORD_PLAIN)
        return false;
    uint8_t raw[RAW_MAX] = {0};
    for (size_t i = 0; i < raw_length; ++i) {
        unsigned char hi = (unsigned char)token[RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * i];
        unsigned char lo = (unsigned char)token[RELAY_PASSWORD_TOKEN_PREFIX_LENGTH + 2 * i + 1];
        if (!hex_digit(hi) || !hex_digit(lo)) {
            mbedtls_platform_zeroize(raw, sizeof(raw));
            return false;
        }
        raw[i] = (uint8_t)((hex_value(hi) << 4) | hex_value(lo));
    }
    const uint8_t *nonce = raw, *cipher = raw + NONCE_SIZE, *tag = cipher + cipher_length;
    uint8_t key[32] = {0};
    if (!remote_presence_derive_key(keyPurpose, key)) {
        mbedtls_platform_zeroize(raw, sizeof(raw));
        return false;
    }
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    uint8_t associated[sizeof(aadDomain) - 1 + 16];
    size_t associated_length = aad(associated, serial);
    int err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!err)
        err = mbedtls_gcm_auth_decrypt(&gcm, cipher_length, nonce, NONCE_SIZE, associated,
                                       associated_length, tag, TAG_SIZE, cipher, (uint8_t *)plain);
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(associated, sizeof(associated));
    mbedtls_platform_zeroize(raw, sizeof(raw));
    if (err || !relay_config_password_plain(plain, cipher_length)) {
        mbedtls_platform_zeroize(plain, plain_capacity);
        return false;
    }
    *plain_length = cipher_length;
    return true;
}

bool relay_password_config_valid(const relay_config_t *config, const uint8_t serial[16]) {
    if (!config || !serial) return false;
    if (config->network_count > RELAY_MAX_NETWORKS) return false;
    for (unsigned i = 0; i < config->network_count; ++i) {
        const relay_network_t *network = &config->networks[i];
        if (!network->password_length) continue;
        if (relay_config_password_token(network->password, network->password_length)) {
            char plain[RELAY_MAX_PASSWORD_PLAIN];
            size_t length = 0;
            bool ok = relay_password_open(serial, network->password, network->password_length,
                                          plain, sizeof(plain), &length);
            mbedtls_platform_zeroize(plain, sizeof(plain));
            if (!ok) return false;
        } else if (!relay_config_password_plain(network->password, network->password_length)) {
            return false;
        }
    }
    return true;
}

bool relay_password_resolve_config(relay_config_t *config, const uint8_t serial[16]) {
    if (!config || !serial) return false;
    if (config->network_count > RELAY_MAX_NETWORKS) return false;
    for (unsigned i = 0; i < config->network_count; ++i) {
        relay_network_t *network = &config->networks[i];
        if (!network->password_length) continue;
        if (!relay_config_password_token(network->password, network->password_length)) {
            if (!relay_config_password_plain(network->password, network->password_length)) return false;
            continue;
        }
        char plain[RELAY_MAX_PASSWORD_PLAIN];
        size_t length = 0;
        bool ok = relay_password_open(serial, network->password, network->password_length,
                                      plain, sizeof(plain), &length);
        if (!ok) {
            mbedtls_platform_zeroize(plain, sizeof(plain));
            return false;
        }
        mbedtls_platform_zeroize(network->password, sizeof(network->password));
        memcpy(network->password, plain, length);
        network->password_length = (uint8_t)length;
        mbedtls_platform_zeroize(plain, sizeof(plain));
    }
    return true;
}
#endif
