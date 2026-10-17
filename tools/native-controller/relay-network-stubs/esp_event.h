#pragma once
#include <stdint.h>
typedef int esp_err_t;
typedef const char *esp_event_base_t;
typedef void (*esp_event_handler_t)(void *, esp_event_base_t, int32_t, void *);
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 1
#define ESP_EVENT_ANY_ID -1
#define IP_EVENT_STA_GOT_IP 1
#define IP_EVENT_GOT_IP6 2
#define IP_EVENT_STA_LOST_IP 5
#define WIFI_EVENT_STA_CONNECTED 3
#define WIFI_EVENT_STA_DISCONNECTED 4
#ifdef __cplusplus
extern "C" {
#endif
extern const char *IP_EVENT, *WIFI_EVENT;
esp_err_t esp_event_loop_create_default(void);
esp_err_t esp_event_handler_register(esp_event_base_t base,int32_t id,esp_event_handler_t handler,void *arg);
#ifdef __cplusplus
}
#endif
