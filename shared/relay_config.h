#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is a bounded, versioned wire format, never a dump of a compiler struct.
// It holds no trust material: the device trusts the safe end through its paired
// controller keys and proves itself with its own device key.
#define RELAY_CONFIG_VERSION 1
#define RELAY_MAX_NETWORKS 10
#define RELAY_MAX_SSID 32
// A Wi-Fi passphrase is at most 64 bytes. The wire field also carries the
// device-sealed PF2PW1 token that "读取设备" returns, so it is larger than the
// passphrase it represents. Plaintext and token rules are below.
#define RELAY_MAX_PASSWORD_PLAIN 64
#define RELAY_MAX_PASSWORD 190
#define RELAY_PASSWORD_TOKEN_PREFIX "PF2PW1"
#define RELAY_PASSWORD_TOKEN_PREFIX_LENGTH 6
#define RELAY_PASSWORD_TOKEN_MIN_LENGTH 62
#define RELAY_PASSWORD_TOKEN_MAX_LENGTH 190
#define RELAY_MAX_HOST 253
#define RELAY_CONFIG_HEADER_SIZE 10
#define RELAY_CONFIG_MAX_SIZE (RELAY_CONFIG_HEADER_SIZE + \
    RELAY_MAX_NETWORKS * (6 + RELAY_MAX_SSID + RELAY_MAX_PASSWORD + RELAY_MAX_HOST))

typedef enum {
    RELAY_MODE_LOCAL = 0,
    RELAY_MODE_RELAY = 1
} relay_mode_t;

typedef struct {
    uint8_t ssid_length, password_length, host_length;
    uint16_t port;
    uint8_t ssid[RELAY_MAX_SSID];
    char password[RELAY_MAX_PASSWORD];
    char host[RELAY_MAX_HOST]; // ASCII DNS name or IPv6 literal, without brackets
} relay_network_t;

typedef struct {
    relay_mode_t mode;
    uint8_t network_count;
    relay_network_t networks[RELAY_MAX_NETWORKS];
} relay_config_t;

typedef enum {
    RELAY_CONFIG_OK = 0,
    RELAY_CONFIG_FORMAT,
    RELAY_CONFIG_MODE,
    RELAY_CONFIG_NETWORK_COUNT,
    RELAY_CONFIG_SSID,
    RELAY_CONFIG_PASSWORD,
    RELAY_CONFIG_HOST,
    RELAY_CONFIG_PORT,
    RELAY_CONFIG_CAPACITY
} relay_config_error_t;

// No allocation; decode clears output on every failure, including truncation.
relay_config_error_t relay_config_validate(const relay_config_t *config);
relay_config_error_t relay_config_decode(const uint8_t *wire, size_t length,
                                          relay_config_t *config);
relay_config_error_t relay_config_encode(const relay_config_t *config,
                                          uint8_t *wire, size_t capacity, size_t *length);
void relay_config_clear(relay_config_t *config);

// A plain Wi-Fi passphrase: empty, 8-63 printable ASCII, or exactly 64 hex
// characters (raw WPA PSK). Tokens are device-sealed opaque strings that the
// controller must preserve and write back; only the device can open them.
bool relay_config_password_plain(const char *password, size_t length);
bool relay_config_password_token(const char *password, size_t length);

#ifdef __cplusplus
}
#endif
