#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
bool remote_presence_verify_digest(const uint8_t id[16], const uint8_t digest[32], const uint8_t signature[64]);
bool remote_presence_derive_key(const char *purpose, uint8_t key[32]);
bool remote_presence_pairing(void);
#ifdef ENABLE_RELAY_DIAGNOSTICS
void remote_device_trace(uint8_t kind, uint8_t code, uint16_t value);
#else
static inline void remote_device_trace(uint8_t kind, uint8_t code, uint16_t value) { (void)kind; (void)code; (void)value; }
#endif
void remote_device_init(void);
bool remote_device_local_allowed(void);
bool remote_device_setup_active(void);
uint16_t remote_device_get(uint8_t report, uint8_t *buffer, uint16_t length);
void remote_device_set(uint8_t report, const uint8_t *buffer, uint16_t length);
void remote_device_service(void);
int remote_device_cbor(uint8_t command, const uint8_t *data, size_t length,
                       uint8_t *response, size_t capacity, uint16_t *response_length);
uint8_t remote_device_keepalive(void);
#ifdef __cplusplus
}
#endif
