#pragma once
#include "relay_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Seals one non-empty Wi-Fi passphrase into the ASCII token returned by the
// settings read protocol. The token is bound to this device's serial and its
// device key, so another device (or a host) cannot open it.
bool relay_password_seal(const uint8_t serial[16], const char *plain, size_t plain_length,
                         char *token, size_t token_capacity, size_t *token_length);
bool relay_password_open(const uint8_t serial[16], const char *token, size_t token_length,
                         char *plain, size_t plain_capacity, size_t *plain_length);

// Decrypt every token in place (for the runtime Wi-Fi configuration) or check
// that plaintext and tokens are all valid without changing the configuration.
// A valid plaintext password still has to satisfy relay_config_password_plain.
bool relay_password_resolve_config(relay_config_t *config, const uint8_t serial[16]);
bool relay_password_config_valid(const relay_config_t *config, const uint8_t serial[16]);

#ifdef __cplusplus
}
#endif
