#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE) && defined(ENABLE_RELAY_DIAGNOSTICS)
#include "relay_diagnostics.h"
#include "../../shared/relay_diagnostics.h"
#include "pico_keys.h"
#include "remote_presence.h"
#include "relay_network.h"
#include "tusb.h"
#include "esp_system.h"
#include <string.h>
_Static_assert(sizeof(relay_diag_record_t) == 280, "diagnostic wire layout");
static portMUX_TYPE diag_lock = portMUX_INITIALIZER_UNLOCKED;
static relay_diag_record_t current, reading;
static uint8_t reply[63], read_tx[16];
static bool read_ok;
// USB callbacks append bounded metadata to RAM; no allocation, crypto or IO.
void remote_device_trace(uint8_t kind, uint8_t code, uint16_t value) {
    uint32_t now = board_millis();
    portENTER_CRITICAL(&diag_lock);
    if (kind == RELAY_DIAG_HID) current.last_hid = code;
    if (kind == RELAY_DIAG_CTAP) current.last_ctap = code;
    if (kind == RELAY_DIAG_RESULT) current.last_result = code;
    if (current.total_events != UINT32_MAX) {
        unsigned at = current.total_events++ % RELAY_DIAGNOSTIC_EVENTS;
        current.events[at] = (relay_diag_event_t){now, kind, code, value};
        if (current.count < RELAY_DIAGNOSTIC_EVENTS) ++current.count;
    }
    current.uptime_ms = now;
    portEXIT_CRITICAL(&diag_lock);
}
void relay_diagnostics_init(void) {
    portENTER_CRITICAL(&diag_lock);
    memset(&current, 0, sizeof(current));
    current.reset_reason = (uint32_t)esp_reset_reason(); current.usb = 0xff;
    memset(reply, 0, sizeof(reply)); read_ok = false;
    portEXIT_CRITICAL(&diag_lock);
}
void relay_diagnostics_poll(void) {
    uint8_t network[4]; relay_network_diagnostics(network);
    uint8_t usb = (tud_mounted() ? 1 : 0) | (tud_suspended() ? 2 : 0);
    if (usb != current.usb) { current.usb = usb; remote_device_trace(RELAY_DIAG_USB, usb, 0); }
    if (memcmp(network, current.network, 4)) {
        memcpy(current.network, network, 4);
        remote_device_trace(RELAY_DIAG_NETWORK, network[0], (uint16_t)(network[1] | ((uint16_t)network[3] << 8)));
    }
}
void relay_diagnostics_select(const uint8_t b[63]) {
    enum { pages = (sizeof(reading) + RELAY_DIAGNOSTIC_CHUNK - 1) / RELAY_DIAGNOSTIC_CHUNK };
    if (b[0] || b[1] >= pages) return;
    for (unsigned i = 18; i < 63; ++i) if (b[i]) return;
    if (!b[1]) {
        portENTER_CRITICAL(&diag_lock);
        reading = current; reading.uptime_ms = board_millis();
        memcpy(read_tx, b + 2, 16); read_ok = true;
        portEXIT_CRITICAL(&diag_lock);
    } else if (!read_ok || memcmp(read_tx, b + 2, 16)) return;
    uint8_t out[63] = {0}; memcpy(out, "PDG2", 4); memcpy(out + 4, read_tx, 16);
    out[21] = b[1]; out[22] = pages;
    size_t offset = (size_t)b[1] * RELAY_DIAGNOSTIC_CHUNK, n = sizeof(reading) - offset;
    if (n > RELAY_DIAGNOSTIC_CHUNK) n = RELAY_DIAGNOSTIC_CHUNK;
    out[24] = (uint8_t)n; memcpy(out + 25, (const uint8_t *)&reading + offset, n);
    portENTER_CRITICAL(&diag_lock); memcpy(reply, out, 63); portEXIT_CRITICAL(&diag_lock);
}
bool relay_diagnostics_get(uint8_t out[63]) {
    portENTER_CRITICAL(&diag_lock); memcpy(out, reply, 63); portEXIT_CRITICAL(&diag_lock);
    return !memcmp(out, "PDG2", 4);
}
#endif
