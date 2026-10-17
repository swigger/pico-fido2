#pragma once
#include "relay_config.h"

// Immutable runtime configuration with passwords resolved to plaintext. NULL
// unless relay mode is active and storage validated. The bytes are never
// returned over USB; GET 19 serves a separate view with sealed password tokens.
// New settings take effect on reboot.
const relay_config_t *relay_firmware_config(void);
// Called only for metadata authenticated by the paired TLS controller and
// bound to the current request. Public hints, never an authorization decision.
void relay_firmware_discovery(const uint8_t metadata[25]);
