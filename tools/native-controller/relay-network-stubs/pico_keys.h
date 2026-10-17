#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#define __ATOMIC_ACQUIRE 0
#define __ATOMIC_RELEASE 0
#define __ATOMIC_ACQ_REL 0
#define __atomic_load_n(p,o) test_atomic_load8(p)
#define __atomic_store_n(p,v,o) test_atomic_store8(p,v)
#define __atomic_sub_fetch(p,v,o) test_atomic_decrement(p)
#define pdMS_TO_TICKS(n) ((n) / 10)
#ifdef __cplusplus
extern "C" {
#endif
extern const char pico_serial_str[17];
extern bool cancel_button;
uint8_t test_atomic_load8(const void *p);
void test_atomic_store8(void *p, uint8_t value);
int test_atomic_decrement(int *p);
uint32_t board_millis(void);
void vTaskDelay(unsigned delay);
#ifdef __cplusplus
}
#endif
