#pragma once
// Preincluded only in RelayDispatchTests. Retain the real APDU/USB/CTAP headers,
// and replace the board/FreeRTOS layer that those headers normally import.
#define _PICO_KEYS_H_
#define __ESP_COMPAT_H_
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "compat.h"
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define DEBUG_DATA(...) ((void)0)
#define DEBUG_PAYLOAD(...) ((void)0)
#define PICOKEY_OK 0
#define PICOKEY_ERR_BLOCKED -4
#define PICOKEY_ERR_FILE_NOT_FOUND -5
#define PICOKEY_EXEC_ERROR -6
#define PICOKEY_ERR_MEMORY_FATAL -7
#define PICOKEY_ERR_NULL_PARAM -8
#define MODE_PROCESSING 1
#define SW_CLA_NOT_SUPPORTED() set_res_sw(0x6e, 0)
#define SW_FILE_NOT_FOUND() set_res_sw(0x6a, 0x82)
#define SW_OK() set_res_sw(0x90, 0)
typedef unsigned queue_t;
typedef unsigned portMUX_TYPE;
typedef struct { uint8_t id[16]; } test_serial_t;
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(lock) ((void)(lock))
#define taskEXIT_CRITICAL(lock) ((void)(lock))
#ifdef _MSC_VER // GCC/Clang provide these builtins
#define __ATOMIC_RELEASE 0
#define __atomic_store_n(ptr,value,order) (*(ptr) = (value))
#endif
#define pdMS_TO_TICKS(n) (n)
#ifdef __cplusplus
extern "C" {
#endif
extern test_serial_t pico_serial;
uint32_t board_millis(void);
void sleep_ms(unsigned ms);
void vTaskDelay(unsigned ms);
void queue_remove_blocking(queue_t *queue, uint32_t *value);
void queue_add_blocking(queue_t *queue, const uint32_t *value);
void led_set_mode(unsigned mode);
bool is_req_button_pending(void);
static inline uint16_t make_uint16_t_be(uint8_t a, uint8_t b) { return (uint16_t)((a << 8) | b); }
static inline uint16_t get_uint16_t_be(const uint8_t *p) { return make_uint16_t_be(p[0], p[1]); }
static inline uint8_t put_uint16_t_be(uint16_t v, uint8_t *p) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }
#ifdef __cplusplus
}
#endif
