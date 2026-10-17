#pragma once
#include <stdlib.h>
// Only the actual network translation unit uses these allocation observers.
// They let tests verify the two DNS references, including delayed callbacks.
void *test_dns_calloc(size_t count,size_t size);
void test_dns_free(void *pointer);
#define calloc test_dns_calloc
#define free test_dns_free
