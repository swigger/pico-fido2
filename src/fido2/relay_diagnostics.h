#pragma once
#include <stdbool.h>
#include <stdint.h>
#if defined(ENABLE_RELAY_DIAGNOSTICS)
void relay_diagnostics_init(void);
void relay_diagnostics_poll(void);
void relay_diagnostics_select(const uint8_t bytes[63]);
bool relay_diagnostics_get(uint8_t bytes[63]);
#else
static inline void relay_diagnostics_init(void) {}
static inline void relay_diagnostics_poll(void) {}
static inline void relay_diagnostics_select(const uint8_t bytes[63]) { (void)bytes; }
static inline bool relay_diagnostics_get(uint8_t bytes[63]) { (void)bytes; return false; }
#endif
