#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DEVICE_RESTART_REPORT 22
#define DEVICE_RESTART_SIGNATURE_REPORT 23
#define DEVICE_RESTART_TIMEOUT 10000u
#define DEVICE_RESTART_DELAY 500u
enum { DEVICE_RESTART_IDLE, DEVICE_RESTART_CHALLENGE, DEVICE_RESTART_ACCEPTED, DEVICE_RESTART_FAILED };
enum { DEVICE_RESTART_OK, DEVICE_RESTART_INVALID, DEVICE_RESTART_BUSY, DEVICE_RESTART_AUTH, DEVICE_RESTART_EXPIRED };
typedef struct {
    uint8_t serial[16], transaction[16], nonce[32], signature[64], parts, phase, result;
    uint32_t started;
    bool (*random)(uint8_t nonce[32]);
    bool (*verify)(const uint8_t id[16], const uint8_t *message, size_t length, const uint8_t signature[64]);
} device_restart_t;
void device_restart_init(device_restart_t *s, const uint8_t serial[16],
    bool (*random)(uint8_t[32]), bool (*verify)(const uint8_t[16], const uint8_t *, size_t, const uint8_t[64]));
// SET 22: opcode 1 begin / 2 execute, tx[1..16], controller ID[17..32] (execute only).
// SET 23: signature half index[0], tx[1..16], signature[17..48]. Reserved bytes must be zero.
void device_restart_set(device_restart_t *s, uint8_t report, const uint8_t bytes[63], uint32_t now, bool busy);
void device_restart_get(const device_restart_t *s, uint8_t bytes[63]);
bool device_restart_poll(device_restart_t *s, uint32_t now, bool busy);
size_t device_restart_message(const device_restart_t *s, const uint8_t id[16], uint8_t out[128]);
#ifdef __cplusplus
}
#endif
