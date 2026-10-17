#pragma once
#include "../lwip/sockets.h"
#ifdef __cplusplus
extern "C" {
#endif
int test_settimeofday(const struct test_timeval *time,const void *timezone);
#ifdef __cplusplus
}
#else
#define settimeofday test_settimeofday
#endif
