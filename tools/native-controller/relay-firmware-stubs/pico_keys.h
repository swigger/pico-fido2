#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
typedef unsigned portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#ifdef __cplusplus
extern "C" {
#endif
#include "../../../pico-keys-sdk/src/led/led.h"
extern led_driver_t led_driver_neopixel;
typedef struct { unsigned opts; uint8_t led_driver, led_gpio; bool led_driver_present, led_gpio_present; } test_phy_data_t;
extern test_phy_data_t phy_data;
#define PHY_OPT_LED_STEADY 1
#define PHY_LED_DRIVER_NEOPIXEL 1
extern const char pico_serial_str[17];
uint32_t board_millis(void);
void test_enter_critical(portMUX_TYPE *lock);
void test_exit_critical(portMUX_TYPE *lock);
#ifdef __cplusplus
}
#endif
#define portENTER_CRITICAL(lock) test_enter_critical(lock)
#define portEXIT_CRITICAL(lock) test_exit_critical(lock)
