#pragma once
#include "relay_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RELAY_SETUP_TIMEOUT_MS 120000u
#define RELAY_SETUP_HOLD_MS 1000u
#define RELAY_SETUP_CONTEXT_SIZE (sizeof("pico-fido2 relay setup v1") + 16 + 16 + 16 + 32 + 4)

typedef enum {
    RELAY_SETUP_IDLE = 0,
    RELAY_SETUP_RECEIVING,
    RELAY_SETUP_VERIFY,
    RELAY_SETUP_RELEASE,
    RELAY_SETUP_PRESS,
    RELAY_SETUP_HOLD,
    RELAY_SETUP_RELEASE_TO_SAVE,
    RELAY_SETUP_DONE,
    RELAY_SETUP_ERROR,
    RELAY_SETUP_CANCELED,
    RELAY_SETUP_EXPIRED
} relay_setup_phase_t;

typedef enum {
    RELAY_SETUP_SUCCESS = 0,
    RELAY_SETUP_INVALID,
    RELAY_SETUP_UNAUTHORIZED,
    RELAY_SETUP_BUSY,
    RELAY_SETUP_STORAGE,
    RELAY_SETUP_RANDOM,
    RELAY_SETUP_TIMEOUT,
    RELAY_SETUP_ABORTED
} relay_setup_result_t;

typedef struct {
    void *user;
    bool (*random)(void *user, uint8_t nonce[32]);
    // Verify against a CURRENTLY trusted controller. The signature is P-256,
    // raw r||s, over SHA-256(context || exact wire bytes). Also validate the
    // configured DER trust anchor using the platform's X.509 implementation.
    bool (*verify)(void *user, const uint8_t key_id[16], const uint8_t *context,
                   size_t context_length, const uint8_t *wire, size_t wire_length,
                   const uint8_t signature[64], const relay_config_t *config);
    // Durable atomic replacement; never touch FIDO credential storage. On
    // ambiguous IO failures the platform must block all credential operations.
    // Apply the new mode only on reboot, after validating the stored snapshot.
    bool (*persist)(void *user, const uint8_t *wire, size_t wire_length);
} relay_setup_callbacks_t;

typedef struct {
    relay_setup_phase_t phase;
    relay_setup_result_t result;
    uint32_t started, pressed;
    size_t expected, received;
    uint8_t serial[16], transaction[16], nonce[32], key_id[16], signature[64];
    uint8_t wire[RELAY_CONFIG_MAX_SIZE];
    relay_config_t decoded;
    relay_setup_callbacks_t callbacks;
} relay_setup_t;

// All calls are serialized by the platform. Crypto/storage callbacks must run
// on the application task, not inside a USB ISR/critical section.
void relay_setup_init(relay_setup_t *state, const uint8_t serial[16],
                      relay_setup_callbacks_t callbacks);
bool relay_setup_active(const relay_setup_t *state);
bool relay_setup_begin(relay_setup_t *state, const uint8_t transaction[16],
                       size_t length, uint32_t now, bool authenticator_busy);
bool relay_setup_chunk(relay_setup_t *state, const uint8_t transaction[16],
                       size_t offset, const uint8_t *bytes, size_t length, uint32_t now);
bool relay_setup_seal(relay_setup_t *state, const uint8_t transaction[16],
                      const uint8_t key_id[16], const uint8_t signature[64], uint32_t now);
bool relay_setup_cancel(relay_setup_t *state, const uint8_t transaction[16]);
void relay_setup_poll(relay_setup_t *state, bool authenticator_busy, bool button_pressed,
                      uint32_t now);
// Public challenge context; does not contain Wi-Fi passwords.
void relay_setup_auth_context(const relay_setup_t *state, uint8_t *context);

#ifdef __cplusplus
}
#endif
