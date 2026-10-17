#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
bool remote_presence_verify_any(const uint8_t digest[32], const uint8_t signature[64]);
bool remote_presence_device_sign(const uint8_t digest[32], uint8_t signature[64]);
#ifdef __cplusplus
}
#endif
