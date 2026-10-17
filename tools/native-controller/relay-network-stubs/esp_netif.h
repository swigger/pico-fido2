#pragma once
#include "esp_event.h"
typedef struct { int unused; } esp_netif_t;
typedef struct { uint32_t addr[4]; } test_ip6_t;
typedef struct { struct { test_ip6_t ip; } ip6_info; } ip_event_got_ip6_t;
typedef enum { ESP_IP6_ADDR_IS_LINK_LOCAL, ESP_IP6_ADDR_IS_GLOBAL, ESP_IP6_ADDR_IS_UNIQUE_LOCAL } esp_ip6_addr_type_t;
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t esp_netif_init(void);
esp_netif_t *esp_netif_create_default_wifi_sta(void);
esp_ip6_addr_type_t esp_netif_ip6_get_addr_type(const test_ip6_t *ip);
esp_err_t esp_netif_create_ip6_linklocal(esp_netif_t *netif);
#ifdef __cplusplus
}
#endif
