#include "relay_transport.h"
#include <string.h>

static const uint8_t challenge_magic[8] = {'P','F','2','C','H','L','0','1'};
static const uint8_t request_magic[8] = {'P','F','2','R','E','Q','0','3'};
static const uint8_t frame_magic[4] = {'P','F','2','F'};
void relay_transport_clear(void *data, size_t length) {
    volatile uint8_t *p = data; while (length--) *p++ = 0;
}
static bool nonzero(const uint8_t *p, size_t n) {
    uint8_t value = 0; for (size_t i = 0; i < n; ++i) value |= p[i]; return value != 0;
}
static bool serial_valid(const uint8_t *p) {
    for (unsigned i = 0; i < 16; ++i)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f') || (p[i] >= 'A' && p[i] <= 'F'))) return false;
    return true;
}
static void put(uint8_t *p, uint64_t value, unsigned n) {
    for (unsigned i = 0; i < n; ++i) p[i] = (uint8_t)(value >> (8 * i));
}
static uint64_t get(const uint8_t *p, unsigned n) {
    uint64_t value = 0; for (unsigned i = 0; i < n; ++i) value |= (uint64_t)p[i] << (8 * i); return value;
}
bool relay_request_challenge(const uint8_t nonce[32], uint8_t out[RELAY_REQUEST_CHALLENGE_SIZE]) {
    memset(out, 0, RELAY_REQUEST_CHALLENGE_SIZE);
    if (!nonce || !nonzero(nonce, 32)) return false;
    memcpy(out, challenge_magic, 8); memcpy(out + 8, nonce, 32); return true;
}
bool relay_request_challenge_parse(const uint8_t *wire, size_t length, uint8_t nonce[32]) {
    memset(nonce, 0, 32);
    if (!wire || length != RELAY_REQUEST_CHALLENGE_SIZE || memcmp(wire, challenge_magic, 8) || !nonzero(wire + 8, 32)) return false;
    memcpy(nonce, wire + 8, 32); return true;
}
static bool request_fields_valid(const relay_request_header_t *h) {
    return h && (h->version == 0 || h->version == 3 || h->version == 4) && serial_valid(h->serial) && nonzero(h->request_id, 16) && nonzero(h->boot_id, 16) && h->length && h->length <= RELAY_CTAP_MAX;
}
static bool request_valid(const relay_request_header_t *h) { return request_fields_valid(h) && nonzero(h->signature, 64); }
bool relay_request_context(const relay_request_header_t *h, const uint8_t nonce[32], const uint8_t request_hash[32],
                           uint8_t out[RELAY_REQUEST_CONTEXT_SIZE]) {
    memset(out, 0, RELAY_REQUEST_CONTEXT_SIZE);
    if (!request_fields_valid(h) || !nonce || !nonzero(nonce, 32) || !request_hash) return false;
    static const char domain[] = "pico-fido2 relay request v1";
    size_t n = 0;
    memcpy(out, domain, sizeof(domain)); n += sizeof(domain);
    if (h->version == 4) out[sizeof(domain) - 2] = '2'; // bind negotiation to the device signature
    memcpy(out + n, challenge_magic, 8); memcpy(out + n + 8, nonce, 32); n += RELAY_REQUEST_CHALLENGE_SIZE;
    memcpy(out + n, h->serial, 16); memcpy(out + n + 16, h->request_id, 16); memcpy(out + n + 32, h->boot_id, 16); n += 48;
    put(out + n, h->length, 2); memcpy(out + n + 2, request_hash, 32); return true;
}
bool relay_request_encode(const relay_request_header_t *h, uint8_t out[RELAY_REQUEST_HEADER_SIZE]) {
    memset(out, 0, RELAY_REQUEST_HEADER_SIZE); if (!request_valid(h)) return false;
    memcpy(out, request_magic, 8); if (h->version == 4) out[7] = '4';
    memcpy(out + 8, h->serial, 16); memcpy(out + 24, h->request_id, 16);
    memcpy(out + 40, h->boot_id, 16); put(out + 56, h->length, 2); memcpy(out + 58, h->signature, 64); return true;
}
bool relay_request_decode(const uint8_t *wire, size_t length, relay_request_header_t *h) {
    memset(h, 0, sizeof(*h));
    if (!wire || length != RELAY_REQUEST_HEADER_SIZE || memcmp(wire, request_magic, 7) || (wire[7] != '3' && wire[7] != '4')) return false;
    h->version = (uint8_t)(wire[7] - '0');
    memcpy(h->serial, wire + 8, 16); memcpy(h->request_id, wire + 24, 16); memcpy(h->boot_id, wire + 40, 16);
    h->length = (uint16_t)get(wire + 56, 2); memcpy(h->signature, wire + 58, 64);
    if (request_valid(h)) return true;
    relay_transport_clear(h, sizeof(*h)); return false;
}
static bool frame_valid(const relay_frame_header_t *h) {
    if (!h || !nonzero(h->request_id, 16)) return false;
    return (h->type == RELAY_FRAME_RESPONSE && h->length >= 1 && h->length <= RELAY_CTAP_MAX) ||
        (h->type == RELAY_FRAME_KEEPALIVE && h->length == 1) || (h->type == RELAY_FRAME_CANCEL && h->length == 0) ||
        (h->type == RELAY_FRAME_DISCOVERY && h->length == RELAY_DISCOVERY_SIZE);
}
bool relay_frame_encode(const relay_frame_header_t *h, uint8_t out[RELAY_FRAME_HEADER_SIZE]) {
    memset(out, 0, RELAY_FRAME_HEADER_SIZE); if (!frame_valid(h)) return false;
    memcpy(out, frame_magic, 4); out[4] = (uint8_t)h->type; put(out + 6, h->length, 2);
    memcpy(out + 8, h->request_id, 16); memcpy(out + 24, h->request_hash, 32); return true;
}
bool relay_frame_decode(const uint8_t *wire, size_t length, relay_frame_header_t *h) {
    memset(h, 0, sizeof(*h));
    if (!wire || length != RELAY_FRAME_HEADER_SIZE || memcmp(wire, frame_magic, 4) || wire[5]) return false;
    h->type = (relay_frame_type_t)wire[4]; h->length = (uint16_t)get(wire + 6, 2);
    memcpy(h->request_id, wire + 8, 16); memcpy(h->request_hash, wire + 24, 32);
    if (frame_valid(h)) return true;
    memset(h, 0, sizeof(*h)); return false;
}
bool relay_frame_payload(const relay_frame_header_t *h, const uint8_t *payload, size_t length) {
    if (!frame_valid(h) || length != h->length || (length && !payload)) return false;
    if (h->type == RELAY_FRAME_CANCEL) return true;
    if (h->type == RELAY_FRAME_KEEPALIVE) return payload[0] == 1 || payload[0] == 2;
    if (h->type == RELAY_FRAME_DISCOVERY) return nonzero(payload, 16) && nonzero(payload + 16, 8) && payload[24] <= 1;
    return payload[0] == 0 || length == 1; // Error replies cannot smuggle a CBOR body.
}
bool relay_frame_matches(const relay_frame_header_t *h, const uint8_t id[16], const uint8_t hash[32]) {
    return frame_valid(h) && id && hash && !memcmp(h->request_id, id, 16) && !memcmp(h->request_hash, hash, 32);
}
