#pragma once
#define GPIO_NUM_0 0
#define GPIO_NUM_27 27
#ifdef __cplusplus
extern "C" {
#endif
int gpio_get_level(int pin);
#ifdef __cplusplus
}
#endif
