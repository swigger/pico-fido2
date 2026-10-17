#pragma once
#include <stdint.h>
#define RELAY_DIAGNOSTIC_REPORT 24
#define RELAY_DIAGNOSTIC_EVENTS 32
#define RELAY_DIAGNOSTIC_CHUNK 38
// Development builds only; numeric metadata, never request/account/key bytes.
enum { RELAY_DIAG_USB = 1, RELAY_DIAG_HID = 2, RELAY_DIAG_CTAP = 3,
       RELAY_DIAG_RESULT = 4, RELAY_DIAG_NETWORK = 5, RELAY_DIAG_RESTART = 6 };
typedef struct { uint32_t ms; uint8_t kind, code; uint16_t value; } relay_diag_event_t;
typedef struct {
    uint32_t reset_reason, uptime_ms, total_events;
    uint16_t count;
    uint8_t usb, reserved, network[4], last_hid, last_ctap, last_result, padding;
    relay_diag_event_t events[RELAY_DIAGNOSTIC_EVENTS];
} relay_diag_record_t; // 280 bytes, little endian; RAM only.
