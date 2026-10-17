#pragma once
#include "esp_event.h"
#define WIFI_STORAGE_RAM 1
#define WIFI_MODE_STA 1
#define WIFI_PS_MIN_MODEM 2
#define WIFI_IF_STA 0
#define WIFI_AUTH_WPA2_PSK 3
#define WIFI_AUTH_OPEN 0
#define ESP_ERR_WIFI_NOT_CONNECT 0x300f
typedef struct { int nvs_enable; } wifi_init_config_t;
typedef struct { uint8_t reason; } wifi_event_sta_disconnected_t;
typedef struct { uint8_t bssid[6]; } wifi_ap_record_t;
#define WIFI_INIT_CONFIG_DEFAULT() {1}
typedef struct { struct { uint8_t ssid[32],password[64]; struct { int authmode; } threshold; } sta; } wifi_config_t;
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t esp_wifi_init(const wifi_init_config_t *config);
esp_err_t esp_wifi_set_storage(int mode);
esp_err_t esp_wifi_set_mode(int mode);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_set_ps(int mode);
esp_err_t esp_wifi_disconnect(void);
esp_err_t esp_wifi_set_config(int interface_id,const wifi_config_t *config);
esp_err_t esp_wifi_connect(void);
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap);
#ifdef __cplusplus
}
#endif
