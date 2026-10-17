#include "device_restart.h"
#include <string.h>
static bool zeros(const uint8_t *p, size_t n) { uint8_t v = 0; while (n--) v |= *p++; return v == 0; }
static void clear(device_restart_t *s) { memset(s->nonce, 0, 32); memset(s->signature, 0, 64); s->parts = 0; }
static void fail(device_restart_t *s, uint8_t result) { clear(s); s->phase = DEVICE_RESTART_FAILED; s->result = result; }
void device_restart_init(device_restart_t *s, const uint8_t serial[16],
    bool (*random)(uint8_t[32]), bool (*verify)(const uint8_t[16], const uint8_t *, size_t, const uint8_t[64])) {
    memset(s, 0, sizeof(*s)); memcpy(s->serial, serial, 16); s->random = random; s->verify = verify;
}
size_t device_restart_message(const device_restart_t *s, const uint8_t id[16], uint8_t out[128]) {
    static const char domain[] = "pico-fido2 device restart v1";
    size_t n = sizeof(domain); memcpy(out, domain, n);
    memcpy(out + n, s->serial, 16); n += 16;
    memcpy(out + n, s->transaction, 16); n += 16;
    memcpy(out + n, id, 16); n += 16;
    memcpy(out + n, s->nonce, 32); return n + 32;
}
void device_restart_set(device_restart_t *s, uint8_t report, const uint8_t b[63], uint32_t now, bool busy) {
    if (s->phase == DEVICE_RESTART_ACCEPTED) return; // A replay cannot postpone/repeat a scheduled restart.
    if (report == DEVICE_RESTART_REPORT && b[0] == 1 && !zeros(b + 1, 16) && zeros(b + 17, 46)) {
        clear(s); memcpy(s->transaction, b + 1, 16); s->result = DEVICE_RESTART_OK;
        if (busy) { fail(s, DEVICE_RESTART_BUSY); return; }
        if (!s->random || !s->random(s->nonce)) { fail(s, DEVICE_RESTART_AUTH); return; }
        s->started = now; s->phase = DEVICE_RESTART_CHALLENGE; return;
    }
    if (s->phase != DEVICE_RESTART_CHALLENGE || memcmp(s->transaction, b + 1, 16)) { fail(s, DEVICE_RESTART_INVALID); return; }
    if (now - s->started >= DEVICE_RESTART_TIMEOUT) { fail(s, DEVICE_RESTART_EXPIRED); return; }
    if (busy) { fail(s, DEVICE_RESTART_BUSY); return; }
    if (report == DEVICE_RESTART_SIGNATURE_REPORT && b[0] < 2 && b[0] == s->parts && zeros(b + 49, 14)) {
        memcpy(s->signature + 32 * s->parts++, b + 17, 32); return;
    }
    if (report == DEVICE_RESTART_REPORT && b[0] == 2 && s->parts == 2 && zeros(b + 33, 30)) {
        uint8_t message[128]; size_t n = device_restart_message(s, b + 17, message);
        bool authorized = s->verify && s->verify(b + 17, message, n, s->signature);
        clear(s);
        if (!authorized) { fail(s, DEVICE_RESTART_AUTH); return; }
        s->phase = DEVICE_RESTART_ACCEPTED; s->started = now; return;
    }
    fail(s, DEVICE_RESTART_INVALID);
}
void device_restart_get(const device_restart_t *s, uint8_t out[63]) {
    memset(out, 0, 63); memcpy(out, "PRS1", 4);
    out[4] = s->phase; out[5] = s->result; out[6] = s->parts;
    memcpy(out + 8, s->transaction, 16);
    if (s->phase == DEVICE_RESTART_CHALLENGE) memcpy(out + 24, s->nonce, 32);
}
bool device_restart_poll(device_restart_t *s, uint32_t now, bool busy) {
    if (s->phase != DEVICE_RESTART_CHALLENGE && s->phase != DEVICE_RESTART_ACCEPTED) return false;
    if (busy) { fail(s, DEVICE_RESTART_BUSY); return false; }
    if (s->phase == DEVICE_RESTART_CHALLENGE) {
        if (now - s->started >= DEVICE_RESTART_TIMEOUT) fail(s, DEVICE_RESTART_EXPIRED);
        return false;
    }
    if (now - s->started < DEVICE_RESTART_DELAY) return false;
    s->phase = DEVICE_RESTART_IDLE; return true;
}
