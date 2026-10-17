#pragma once
#include "relay_setup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RELAY_HID_STATUS 16
#define RELAY_HID_CHALLENGE 17
#define RELAY_HID_DIGEST 18
#define RELAY_HID_SEAL 19
// GET 19 returns a snapshot of the sealed configuration. SET 16 with opcode 5
// selects the 38-byte page; the report is idempotent so a retried GET is safe.
#define RELAY_HID_READ 19
#define RELAY_HID_READ_OPCODE 5
#define RELAY_HID_READ_CHUNK_SIZE 38
#define RELAY_HID_READ_MAGIC "PRD1"
#define RELAY_HID_REPORT_SIZE 63
#define RELAY_HID_CHUNK_SIZE 39

// SET uses report 16 begin/cancel/read, 17 data, 18 signature halves, 19 seal.
// Every SET: opcode[1], sequence LE32[4], transaction[16], command fields.
enum { RELAY_HID_CANCEL = 0, RELAY_HID_BEGIN = 1, RELAY_HID_DATA = 2,
       RELAY_HID_SIGNATURE = 3, RELAY_HID_FINISH = 4, RELAY_HID_READ_REQUEST = 5 };
enum { RELAY_HID_OK = 0, RELAY_HID_BAD_REPORT, RELAY_HID_BAD_TRANSACTION,
       RELAY_HID_BAD_SEQUENCE, RELAY_HID_BAD_STATE };
enum { RELAY_HID_STORAGE_READY = 1, RELAY_HID_BOOT_FAULT = 2, RELAY_HID_REBOOT_REQUIRED = 4 };

typedef struct {
    relay_setup_t setup;
    uint32_t sequence;
    uint8_t command_result;
    uint8_t signature[64], signature_parts;
    uint8_t running_mode, stored_mode, running_networks, stored_networks, flags;
    uint8_t stored_digest[32];
    // Sealed configuration snapshot for GET 19. The platform republishes it on
    // boot and after a save; a read transaction is a consistent copy.
    uint8_t read_wire[RELAY_CONFIG_MAX_SIZE];
    uint16_t read_length, read_offset;
    uint8_t read_transaction[16];
    bool read_active;
} relay_hid_t;

// Application-task API. The platform serializes SETs and publishes GET snapshots.
void relay_hid_init(relay_hid_t *state, const uint8_t serial[16], relay_setup_callbacks_t callbacks);
void relay_hid_publish_config(relay_hid_t *state, const uint8_t *wire, size_t length);
void relay_hid_set(relay_hid_t *state, uint8_t report, const uint8_t bytes[63], uint32_t now, bool busy);
void relay_hid_poll(relay_hid_t *state, uint32_t now, bool busy, bool pressed);
bool relay_hid_get(const relay_hid_t *state, uint8_t report, uint8_t out[63], uint32_t now);

#ifdef __cplusplus
}
#endif
