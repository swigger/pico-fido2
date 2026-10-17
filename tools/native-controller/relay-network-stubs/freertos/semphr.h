#pragma once
typedef void *SemaphoreHandle_t;
#define pdTRUE 1
#ifdef __cplusplus
extern "C" {
#endif
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t mutex, unsigned ticks);
int xSemaphoreGive(SemaphoreHandle_t mutex);
int xTaskCreate(void (*entry)(void *), const char *name, unsigned stack, void *argument, unsigned priority, void *handle);
#ifdef __cplusplus
}
#endif
