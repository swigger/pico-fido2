#pragma once
#include <stdbool.h>
#include <stddef.h>
typedef int esp_err_t;
typedef enum { EFUSE_BLK_KEY3 = 7, EFUSE_BLK_KEY4 = 8 } esp_efuse_block_t;
typedef enum { ESP_EFUSE_KEY_PURPOSE_USER = 0, TEST_OTHER_PURPOSE = 1 } esp_efuse_purpose_t;
typedef struct { esp_efuse_block_t block; } esp_efuse_desc_t;
#define ESP_OK 0
#define ESP_FAIL (-1)
#ifdef __cplusplus
extern "C" {
#endif
bool esp_efuse_key_block_unused(esp_efuse_block_t block);
bool esp_efuse_get_key_dis_read(esp_efuse_block_t block);
esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t block);
const esp_efuse_desc_t **esp_efuse_get_key(esp_efuse_block_t block);
esp_err_t esp_efuse_read_field_blob(const esp_efuse_desc_t *field[], void *destination, size_t bits);
/* No write, burn or protection API is provided: an accidental call fails to link. */
#ifdef __cplusplus
}
#endif
