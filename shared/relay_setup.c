#include "relay_setup.h"
#include <string.h>

static void wipe(void *buffer, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length--) *p++ = 0;
}
static void finish(relay_setup_t *s, relay_setup_phase_t phase, relay_setup_result_t result) {
    s->phase = phase;
    s->result = result;
    wipe(s->wire, sizeof(s->wire));
    wipe(s->signature, sizeof(s->signature));
    wipe(s->nonce, sizeof(s->nonce));
    relay_config_clear(&s->decoded);
    s->expected = s->received = 0;
}
bool relay_setup_active(const relay_setup_t *s) {
    return s && s->phase >= RELAY_SETUP_RECEIVING && s->phase <= RELAY_SETUP_RELEASE_TO_SAVE;
}
static bool live(relay_setup_t *s, uint32_t now) {
    if (!relay_setup_active(s)) return false;
    if ((uint32_t)(now - s->started) >= RELAY_SETUP_TIMEOUT_MS) {
        finish(s, RELAY_SETUP_EXPIRED, RELAY_SETUP_TIMEOUT);
        return false;
    }
    return true;
}
void relay_setup_init(relay_setup_t *s, const uint8_t serial[16], relay_setup_callbacks_t callbacks) {
    wipe(s, sizeof(*s));
    memcpy(s->serial, serial, 16);
    s->callbacks = callbacks;
}
bool relay_setup_begin(relay_setup_t *s, const uint8_t transaction[16], size_t length,
                       uint32_t now, bool busy) {
    if (!s || !transaction || relay_setup_active(s)) return false;
    finish(s, RELAY_SETUP_IDLE, RELAY_SETUP_SUCCESS);
    memcpy(s->transaction, transaction, 16);
    if (busy) { finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_BUSY); return false; }
    if (length < RELAY_CONFIG_HEADER_SIZE || length > RELAY_CONFIG_MAX_SIZE) {
        finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_INVALID); return false;
    }
    if (!s->callbacks.random || !s->callbacks.verify || !s->callbacks.persist ||
        !s->callbacks.random(s->callbacks.user, s->nonce)) {
        finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_RANDOM); return false;
    }
    s->phase = RELAY_SETUP_RECEIVING;
    s->started = now;
    s->expected = length;
    memset(s->key_id, 0, 16);
    return true;
}
bool relay_setup_chunk(relay_setup_t *s, const uint8_t tx[16], size_t offset,
                       const uint8_t *bytes, size_t length, uint32_t now) {
    if (!s || !tx || !live(s, now) || s->phase != RELAY_SETUP_RECEIVING ||
        memcmp(tx, s->transaction, 16)) return false;
    if (!bytes || !length || offset != s->received || length > s->expected - s->received) {
        finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_INVALID); return false;
    }
    memcpy(s->wire + s->received, bytes, length);
    s->received += length;
    return true;
}
bool relay_setup_seal(relay_setup_t *s, const uint8_t tx[16], const uint8_t id[16],
                      const uint8_t signature[64], uint32_t now) {
    if (!s || !tx || !id || !signature || !live(s, now) || s->phase != RELAY_SETUP_RECEIVING ||
        memcmp(tx, s->transaction, 16)) return false;
    if (s->received != s->expected) {
        finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_INVALID); return false;
    }
    memcpy(s->key_id, id, 16);
    memcpy(s->signature, signature, 64);
    s->phase = RELAY_SETUP_VERIFY;
    return true;
}
bool relay_setup_cancel(relay_setup_t *s, const uint8_t tx[16]) {
    if (!s || !tx || !relay_setup_active(s) || memcmp(tx, s->transaction, 16)) return false;
    finish(s, RELAY_SETUP_CANCELED, RELAY_SETUP_ABORTED);
    return true;
}
void relay_setup_auth_context(const relay_setup_t *s, uint8_t *context) {
    static const char domain[] = "pico-fido2 relay setup v1";
    memcpy(context, domain, sizeof(domain)); context += sizeof(domain);
    memcpy(context, s->serial, 16); context += 16;
    memcpy(context, s->transaction, 16); context += 16;
    memcpy(context, s->key_id, 16); context += 16;
    memcpy(context, s->nonce, 32); context += 32;
    for (unsigned i = 0; i < 4; ++i) context[i] = (uint8_t)(s->expected >> (8 * i));
}
void relay_setup_poll(relay_setup_t *s, bool busy, bool pressed, uint32_t now) {
    if (!s || !live(s, now)) return;
    if (busy) { finish(s, RELAY_SETUP_CANCELED, RELAY_SETUP_BUSY); return; }
    if (s->phase == RELAY_SETUP_VERIFY) {
        uint8_t context[RELAY_SETUP_CONTEXT_SIZE];
        relay_setup_auth_context(s, context);
        if (relay_config_decode(s->wire, s->expected, &s->decoded) != RELAY_CONFIG_OK) {
            finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_INVALID); return;
        }
        if (!s->callbacks.verify(s->callbacks.user, s->key_id, context, sizeof(context),
                                  s->wire, s->expected, s->signature, &s->decoded)) {
            finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_UNAUTHORIZED); return;
        }
        s->phase = RELAY_SETUP_RELEASE;
    } else if (s->phase == RELAY_SETUP_RELEASE && !pressed) {
        s->phase = RELAY_SETUP_PRESS;
    } else if (s->phase == RELAY_SETUP_PRESS && pressed) {
        s->pressed = now;
        s->phase = RELAY_SETUP_HOLD;
    } else if (s->phase == RELAY_SETUP_HOLD) {
        if (!pressed) s->phase = RELAY_SETUP_PRESS;
        else if ((uint32_t)(now - s->pressed) >= RELAY_SETUP_HOLD_MS)
            s->phase = RELAY_SETUP_RELEASE_TO_SAVE;
    } else if (s->phase == RELAY_SETUP_RELEASE_TO_SAVE && !pressed) {
        // Recheck controller authorization/trust after the physical wait. A
        // controller revoked while waiting must not be able to save settings.
        uint8_t context[RELAY_SETUP_CONTEXT_SIZE];
        relay_setup_auth_context(s, context);
        if (!s->callbacks.verify(s->callbacks.user, s->key_id, context, sizeof(context),
                                  s->wire, s->expected, s->signature, &s->decoded)) {
            finish(s, RELAY_SETUP_ERROR, RELAY_SETUP_UNAUTHORIZED); return;
        }
        bool saved = s->callbacks.persist(s->callbacks.user, s->wire, s->expected);
        finish(s, saved ? RELAY_SETUP_DONE : RELAY_SETUP_ERROR,
                  saved ? RELAY_SETUP_SUCCESS : RELAY_SETUP_STORAGE);
    }
}
