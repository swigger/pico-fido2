#pragma once
typedef void *SemaphoreHandle_t;
#ifdef __cplusplus
extern "C" {
#endif
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t handle, unsigned timeout);
int xSemaphoreGive(SemaphoreHandle_t handle);
#ifdef __cplusplus
}
#endif
