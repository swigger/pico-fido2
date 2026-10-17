idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS . ../../shared ../../pico-keys-sdk/src ../../pico-keys-sdk/src/fs ../../pico-keys-sdk/src/rng ../../pico-keys-sdk/src/usb  ../../pico-keys-sdk/tinycbor/src ../../pico-fido/src ../../pico-openpgp/src
    REQUIRES esp_tinyusb mbedtls efuse nvs_flash esp_wifi esp_event esp_netif lwip esp_pm bootloader_support
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
