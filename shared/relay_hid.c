#include "relay_hid.h"
#include <string.h>

static uint16_t read16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void write16(uint8_t *p, size_t n) { p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); }
static void write32(uint8_t *p, uint32_t n) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(n >> (8 * i));
}
static void clear_signature(relay_hid_t *s) {
    volatile uint8_t *p = s->signature;
    for (unsigned i = 0; i < 64; ++i) p[i] = 0;
    s->signature_parts = 0;
}
static bool zeros(const uint8_t *p, size_t length) {
    uint8_t v = 0;
    for (size_t i = 0; i < length; ++i) v |= p[i];
    return v == 0;
}
void relay_hid_init(relay_hid_t *s, const uint8_t serial[16], relay_setup_callbacks_t callbacks) {
    memset(s, 0, sizeof(*s));
    relay_setup_init(&s->setup, serial, callbacks);
    s->flags = RELAY_HID_BOOT_FAULT; // Never assume local mode before storage has been checked.
}
void relay_hid_publish_config(relay_hid_t *s, const uint8_t *wire, size_t length) {
    if (!s) return;
    s->read_active = false;
    s->read_offset = 0;
    memset(s->read_transaction, 0, sizeof(s->read_transaction));
    if (!wire || !length || length > sizeof(s->read_wire)) {
        s->read_length = 0;
        return;
    }
    memcpy(s->read_wire, wire, length);
    s->read_length = (uint16_t)length;
}
void relay_hid_set(relay_hid_t *s, uint8_t report, const uint8_t b[63], uint32_t now, bool busy) {
    uint32_t seq = read32(b + 1);
    const uint8_t *tx = b + 5;
    s->command_result = RELAY_HID_BAD_REPORT;
    if (report < 16 || report > 19 || !seq) return;
    if (report == 16 && b[0] == RELAY_HID_READ_REQUEST) {
        if (seq != 1 || !zeros(b + 23, 40) || relay_setup_active(&s->setup) || !s->read_length) {
            s->command_result = RELAY_HID_BAD_STATE;
            return;
        }
        uint16_t offset = read16(b + 21);
        if (offset > s->read_length) { s->command_result = RELAY_HID_BAD_STATE; return; }
        if (offset == 0) {
            memcpy(s->read_transaction, tx, 16);
            s->read_active = true;
        } else if (!s->read_active || memcmp(tx, s->read_transaction, 16)) {
            s->command_result = RELAY_HID_BAD_STATE;
            return;
        }
        s->read_offset = offset;
        s->command_result = RELAY_HID_OK;
        return;
    }
    if (report == 16 && b[0] == RELAY_HID_BEGIN) {
        if (seq != 1 || !zeros(b + 23, 40)) return;
        if (relay_setup_active(&s->setup)) { s->command_result = RELAY_HID_BAD_STATE; return; }
        clear_signature(s);
        s->sequence = seq;
        s->command_result = relay_setup_begin(&s->setup, tx, read16(b + 21), now, busy)
            ? RELAY_HID_OK : RELAY_HID_BAD_STATE;
        return;
    }
    if (memcmp(tx, s->setup.transaction, 16)) { s->command_result = RELAY_HID_BAD_TRANSACTION; return; }
    if (s->sequence == UINT32_MAX || seq != s->sequence + 1) { s->command_result = RELAY_HID_BAD_SEQUENCE; return; }
    s->sequence = seq;
    bool ok = false;
    if (report == 16 && b[0] == RELAY_HID_CANCEL && zeros(b + 21, 42)) {
        ok = relay_setup_cancel(&s->setup, tx);
        clear_signature(s);
    } else if (report == 17 && b[0] == RELAY_HID_DATA && b[23] > 0 && b[23] <= 39 &&
               zeros(b + 24 + b[23], 39 - b[23]) && !s->signature_parts) {
        ok = relay_setup_chunk(&s->setup, tx, read16(b + 21), b + 24, b[23], now);
    } else if (report == 18 && b[0] == RELAY_HID_SIGNATURE && b[21] < 2 &&
               zeros(b + 54, 9) && s->setup.phase == RELAY_SETUP_RECEIVING &&
               s->setup.received == s->setup.expected && s->signature_parts == b[21]) {
        memcpy(s->signature + 32 * b[21], b + 22, 32);
        ++s->signature_parts;
        ok = true;
    } else if (report == 19 && b[0] == RELAY_HID_FINISH && zeros(b + 37, 26) && s->signature_parts == 2) {
        ok = relay_setup_seal(&s->setup, tx, b + 21, s->signature, now);
        clear_signature(s);
    }
    s->command_result = ok ? RELAY_HID_OK : RELAY_HID_BAD_STATE;
}
void relay_hid_poll(relay_hid_t *s, uint32_t now, bool busy, bool pressed) {
    relay_setup_poll(&s->setup, busy, pressed, now);
    if (!relay_setup_active(&s->setup)) clear_signature(s);
}
bool relay_hid_get(const relay_hid_t *s, uint8_t report, uint8_t out[63], uint32_t now) {
    memset(out, 0, 63);
    if (report == RELAY_HID_READ) {
        if (!s->read_active || s->read_offset > s->read_length) return false;
        memcpy(out, RELAY_HID_READ_MAGIC, 4);
        memcpy(out + 4, s->read_transaction, 16);
        write16(out + 20, s->read_length);
        write16(out + 22, s->read_offset);
        size_t length = s->read_length - s->read_offset;
        if (length > RELAY_HID_READ_CHUNK_SIZE) length = RELAY_HID_READ_CHUNK_SIZE;
        out[24] = (uint8_t)length;
        memcpy(out + 25, s->read_wire + s->read_offset, length);
        return true;
    }
    if (report < 16 || report > 18) return false;
    memcpy(out, "PRL1", 4);
    uint32_t elapsed = now - s->setup.started;
    uint32_t remaining = relay_setup_active(&s->setup) && elapsed < RELAY_SETUP_TIMEOUT_MS
        ? RELAY_SETUP_TIMEOUT_MS - elapsed : 0;
    if (report == 16) {
        out[4] = (uint8_t)s->setup.phase; out[5] = (uint8_t)s->setup.result;
        out[6] = s->running_mode; out[7] = s->stored_mode;
        out[8] = s->running_networks; out[9] = s->stored_networks; out[10] = s->flags;
        out[11] = RELAY_CONFIG_VERSION;
        write32(out + 12, s->sequence); memcpy(out + 16, s->setup.transaction, 16);
        write16(out + 32, s->setup.received); write16(out + 34, s->setup.expected);
        write32(out + 36, remaining); out[40] = s->command_result; out[41] = s->signature_parts;
    } else if (report == 17) {
        memcpy(out + 4, s->setup.transaction, 16);
        if (remaining) memcpy(out + 20, s->setup.nonce, 32);
        write16(out + 52, s->setup.expected); write32(out + 54, remaining);
    } else {
        memcpy(out + 4, s->stored_digest, 32);
        out[36] = s->flags;
    }
    return true;
}
