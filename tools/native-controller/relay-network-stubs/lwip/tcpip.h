#pragma once
#include "dns.h"
#ifdef __cplusplus
extern "C" {
#endif
err_t tcpip_callback(void (*function)(void *),void *arg);
#ifdef __cplusplus
}
#endif
