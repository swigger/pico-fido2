#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Must fit the current 2048-byte firmware USB buffer (minus HID/status overhead).
#define RELAY_CTAP_MAX 1976u
// Vendor CTAP command: exact RP + complete user name, consented boolean result.
#define RELAY_CTAP_EXACT_QUERY 0x50u
#define RELAY_REQUEST_CHALLENGE_SIZE 40u
#define RELAY_REQUEST_HEADER_SIZE 122u
#define RELAY_REQUEST_CONTEXT_SIZE (sizeof("pico-fido2 relay request v1") + RELAY_REQUEST_CHALLENGE_SIZE + 16u * 3u + 2u + 32u)
#define RELAY_FRAME_HEADER_SIZE 56u
#define RELAY_OPERATION_TIMEOUT_MS 90000u

#define RELAY_DISCOVERY_SIZE 25u // vault ID (16), generation LE64, clientPin (0/1)
typedef enum { RELAY_FRAME_RESPONSE = 1, RELAY_FRAME_KEEPALIVE = 2, RELAY_FRAME_CANCEL = 3, RELAY_FRAME_DISCOVERY = 4 } relay_frame_type_t;
typedef struct {
    uint8_t version; // 0/3: existing protocol; 4: authenticated discovery hints
    uint8_t serial[16], request_id[16], boot_id[16];
    uint16_t length;
    uint8_t signature[64]; // device key, raw r||s over SHA-256(relay_request_context)
} relay_request_header_t;
typedef struct {
    relay_frame_type_t type;
    uint16_t length;
    uint8_t request_id[16], request_hash[32];
} relay_frame_header_t;

// TLS authenticates the safe end without a CA, host name or clock: its per-start
// certificate must carry an ECDSA P-256/SHA-256 signature by a controller key the
// device has paired. No CTAP data may be sent before that check succeeds.
// TLS-only. The safe end first sends a fresh challenge. The device signs it with
// its paired device key, bound to its serial, boot, request ID and the SHA-256
// of the complete CTAP request; the safe end verifies with the pinned public key.
bool relay_request_challenge(const uint8_t nonce[32], uint8_t out[RELAY_REQUEST_CHALLENGE_SIZE]);
bool relay_request_challenge_parse(const uint8_t *wire, size_t length, uint8_t nonce[32]);
bool relay_request_context(const relay_request_header_t *header, const uint8_t nonce[32], const uint8_t request_hash[32],
                           uint8_t out[RELAY_REQUEST_CONTEXT_SIZE]);
// A connection carries exactly one request, keepalives, and a final
// response or cancel. Every following frame is bound to the same ID and SHA-256
// of the complete CTAP request. Never retry a delivered request automatically.
bool relay_request_encode(const relay_request_header_t *header, uint8_t out[RELAY_REQUEST_HEADER_SIZE]);
bool relay_request_decode(const uint8_t *wire, size_t length, relay_request_header_t *header);
bool relay_frame_encode(const relay_frame_header_t *header, uint8_t out[RELAY_FRAME_HEADER_SIZE]);
bool relay_frame_decode(const uint8_t *wire, size_t length, relay_frame_header_t *header);
bool relay_frame_payload(const relay_frame_header_t *header, const uint8_t *payload, size_t length);
bool relay_frame_matches(const relay_frame_header_t *header, const uint8_t request_id[16], const uint8_t request_hash[32]);
void relay_transport_clear(void *data, size_t length);
#ifdef __cplusplus
}
#endif
