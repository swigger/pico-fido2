#pragma once
#include "esp_event.h"
#include <stdbool.h>
#include <stdlib.h>
#define ESP_ERROR_CHECK(expr) do { if ((expr) != ESP_OK) abort(); } while (0)
typedef struct { int max_freq_mhz, min_freq_mhz; bool light_sleep_enable; } esp_pm_config_t;
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t esp_pm_configure(const esp_pm_config_t *config);
#ifdef __cplusplus
}
#endif
