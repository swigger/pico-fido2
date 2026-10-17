#pragma once
#include <stddef.h>
#include <stdint.h>
#include "relay_config.h"
void relay_network_init(void);
void relay_network_start_background(const relay_config_t *config);
// Best-effort background discovery, preempted by a foreground operation.
void relay_network_refresh(const relay_config_t *config);
int relay_network_exchange(const relay_config_t *config, const uint8_t *request, size_t length,
                            uint8_t *response, size_t capacity, uint16_t *response_length);
uint8_t relay_network_keepalive(void);
// Public diagnostics only: phase, Wi-Fi reason, readiness flags, profile index.
// No SSID, addresses, passwords, tokens or credential data.
void relay_network_diagnostics(uint8_t out[4]);
