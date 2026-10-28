#
# This file is part of the Pico FIDO2 distribution (https://github.com/polhenarejos/pico-fido2).
# Copyright (c) 2025 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.13)

set(USB_VID 0x1D50)
set(USB_PID 0x619B)

if(ESP_PLATFORM)
    set(DEBUG_APDU 0)
    option(LED_ACTIVITY_ONLY "Keep the status LED dark when idle" ON)
    if(LED_ACTIVITY_ONLY)
        add_compile_definitions(LED_ACTIVITY_ONLY=1)
    endif()
    option(ENABLE_REMOTE_PRESENCE "Allow signed confirmation from a paired local controller" OFF)
    option(ENABLE_RELAY_DIAGNOSTICS "Development-only USB/relay RAM diagnostics" OFF)
    if(ENABLE_RELAY_DIAGNOSTICS)
        add_compile_definitions(ENABLE_RELAY_DIAGNOSTICS=1)
    endif()
    if(ENABLE_REMOTE_PRESENCE)
        add_compile_definitions(ENABLE_REMOTE_PRESENCE=1)
        set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults;${CMAKE_CURRENT_LIST_DIR}/sdkconfig.relay.defaults")
    endif()
    option(ENABLE_ESP_EFUSE_KEYS "Irreversibly provision ESP32 eFuse key blocks on first boot" OFF)
    if(NOT ENABLE_ESP_EFUSE_KEYS)
        add_compile_definitions(PICO_NO_EFUSE_KEYS=1)
    endif()
    set(EXTRA_COMPONENT_DIRS
        src/fido2
        pico-keys-sdk/src
        pico-keys-sdk/config/esp32/components
    )
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()

    if(NOT ENABLE_EMULATION)
        set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
        include(pico_sdk_import.cmake)
    endif()

    project(pico_fido2 C CXX ASM)

    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    add_executable(pico_fido2)
endif()

option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
if(ENABLE_POWER_ON_RESET)
    add_definitions(-DENABLE_POWER_ON_RESET=1)
    message(STATUS "Power cycle on reset: \t enabled")
else()
    add_definitions(-DENABLE_POWER_ON_RESET=0)
    message(STATUS "Power cycle on reset: \t disabled")
endif()

option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
if(ENABLE_OATH_APP)
    add_definitions(-DENABLE_OATH_APP=1)
    message(STATUS "OATH Application: \t\t enabled")
else()
    message(STATUS "OATH Application: \t\t disabled")
endif()

option(ENABLE_OTP_APP "Enable/disable OTP application" ON)
if(ENABLE_OTP_APP)
    add_definitions(-DENABLE_OTP_APP=1)
    message(STATUS "OTP Application: \t\t enabled")
else()
    message(STATUS "OTP Application: \t\t disabled")
endif()

if(ENABLE_OTP_APP OR ENABLE_OATH_APP)
    set(USB_ITF_CCID 1)
    set(USB_ITF_WCID 1)
else()
    set(USB_ITF_CCID 0)
endif()

set(USB_ITF_HID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)

if(NOT ESP_PLATFORM)
    set(SOURCES ${PICO_KEYS_SOURCES})
endif()

list(APPEND SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/shared/relay_config.c
    ${CMAKE_CURRENT_LIST_DIR}/shared/relay_setup.c
    ${CMAKE_CURRENT_LIST_DIR}/shared/relay_hid.c
    ${CMAKE_CURRENT_LIST_DIR}/shared/device_restart.c
    ${CMAKE_CURRENT_LIST_DIR}/shared/relay_transport.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/relay_firmware.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/relay_diagnostics.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/relay_password.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/relay_network.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/files.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/fido.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/kek.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_register.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_authenticate.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_get_info.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_make_credential.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/known_apps.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_client_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/credential.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_get_assertion.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_selection.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_cred_mgmt.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_config.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_vendor.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_large_blobs.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/management.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/defs.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/openpgp.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/piv.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_select.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_get_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_verify.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_put_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_select_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_import_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_change_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_mse.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_internal_aut.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_challenge.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_activate_file.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_terminate_df.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_pso.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_keypair_gen.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_reset_retry.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/do.c
)
if(ENABLE_OATH_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/oath.c
    )
endif()
if(ENABLE_OTP_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/otp.c
    )
endif()

SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/version.h" 1)
if(ESP_PLATFORM)
    project(pico_fido2)
    # One file for the controller's 刷写新设备: bootloader, partition table and
    # app merged at their flash offsets, written from 0x0.
    if(IDF_TARGET STREQUAL "esp32s3")
        idf_build_get_property(build_dir BUILD_DIR)
        idf_build_get_property(python PYTHON)
        set(merged_image "${build_dir}/esp32s3supermini-${ver_major}.${ver_minor}.bin")
        add_custom_target(merged_image ALL
            COMMAND ${python} -m esptool --chip esp32s3 merge_bin -o "${merged_image}" @flash_args
            WORKING_DIRECTORY "${build_dir}" BYPRODUCTS "${merged_image}" VERBATIM)
        add_dependencies(merged_image app bootloader partition_table_bin)
    endif()
endif()
set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/shared
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src
)
if(NOT ESP_PLATFORM)
    # Certificate upgrades parse and verify the existing device certificate.
    target_sources(mbedtls PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/mbedtls/library/pk_ecc.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/mbedtls/library/pkcs12.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/mbedtls/library/pkparse.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/mbedtls/library/x509.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/mbedtls/library/x509_crt.c
    )
    target_sources(pico_fido2 PUBLIC ${SOURCES})
    target_include_directories(pico_fido2 PUBLIC ${INCLUDES})

    target_compile_options(pico_fido2 PUBLIC
        -Wall
    )
    if(NOT MSVC)
        target_compile_options(pico_fido2 PUBLIC
            -Werror
        )

        # Suppress use-after-free warning for cross-compilers
        string(FIND "${CMAKE_C_COMPILER}" ":" COMPILER_COLON)
        if(${COMPILER_COLON} GREATER_EQUAL 0)
            target_compile_options(pico_fido2 PUBLIC
                -Wno-error=use-after-free
            )
        endif()
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            target_compile_options(pico_fido2 PUBLIC
                -fdata-sections
                -ffunction-sections
            )
        endif()
        if(APPLE)
            target_link_options(pico_fido2 PUBLIC
                -Wl,-dead_strip
            )
        else()
            target_link_options(pico_fido2 PUBLIC
                -Wl,--gc-sections
            )
        endif()
        target_link_libraries(pico_fido2 PRIVATE ${LIBRARIES} pthread m)
    else()
        target_link_libraries(pico_fido2 PRIVATE pico_keys_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id pico_aon_timer tinyusb_device tinyusb_board)
        pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
    endif()
endif()
