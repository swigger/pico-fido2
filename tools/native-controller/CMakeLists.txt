cmake_minimum_required(VERSION 3.21)
project(PicoFidoController LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
# Qt is linked against the dynamic MSVC runtime; use it everywhere.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
option(PICO_CONTROLLER_GUI "Build the Qt controller (Qt 6 or Qt 5.15)" ON)
option(ENABLE_RELAY_DIAGNOSTICS "Development-only USB/relay RAM diagnostics" OFF)

include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(relay_mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(HIDAPI_WITH_LIBUSB OFF CACHE BOOL "" FORCE)
set(HIDAPI_BUILD_HIDTEST OFF CACHE BOOL "" FORCE)
FetchContent_Declare(relay_hidapi
    URL https://github.com/libusb/hidapi/archive/refs/tags/hidapi-0.15.0.tar.gz
    URL_HASH SHA256=5d84dec684c27b97b921d2f3b73218cb773cf4ea915caee317ac8fc73cef8136
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(relay_mbedtls relay_hidapi)

set(SHARED ${CMAKE_CURRENT_SOURCE_DIR}/../../shared)
set(SDK ${CMAKE_CURRENT_SOURCE_DIR}/../../pico-keys-sdk)
if(MSVC)
    set(WARNINGS /W4 /utf-8 /permissive-)
    add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
    set(WARNINGS -Wall -Wextra -Wno-misleading-indentation)
endif()
# Force-include a header for the firmware host fixtures.
function(force_include target header)
    if(MSVC)
        target_compile_options(${target} PRIVATE /FI${header})
    else()
        target_compile_options(${target} PRIVATE -include ${header})
    endif()
endfunction()

add_library(RelayConfig STATIC ${SHARED}/relay_config.c ${SHARED}/relay_setup.c ${SHARED}/relay_hid.c ${SHARED}/relay_transport.c ${SHARED}/device_restart.c)
target_include_directories(RelayConfig PUBLIC ${SHARED})
target_compile_options(RelayConfig PRIVATE ${WARNINGS})

# Everything except the windows: crypto, storage, HID protocols, TLS service, CLI.
add_library(ControllerCore STATIC
    platform.cpp platform_protect.cpp crypto.cpp hid.cpp core.cpp credentials.cpp device_names.cpp
    relay_control.cpp relay_settings.cpp relay_vault.cpp relay_backup.cpp relay_cloud.cpp relay_storage.cpp
    relay_authenticator.cpp relay_attestation.cpp relay_pin.cpp relay_identity.cpp relay_tls.cpp relay_server.cpp relay_profile.cpp
    safe_end_session.cpp esp_flasher.cpp esp_serial.cpp cli.cpp)
target_include_directories(ControllerCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ControllerCore PUBLIC cxx_std_17)
if(ENABLE_RELAY_DIAGNOSTICS)
    target_compile_definitions(ControllerCore PUBLIC ENABLE_RELAY_DIAGNOSTICS=1)
endif()
target_compile_options(ControllerCore PRIVATE ${WARNINGS})
target_link_libraries(ControllerCore PUBLIC RelayConfig mbedtls mbedx509 mbedcrypto hidapi::hidapi)
if(WIN32)
    target_link_libraries(ControllerCore PUBLIC bcrypt crypt32 ws2_32 advapi32 shell32 ole32 setupapi)
elseif(APPLE)
    target_link_libraries(ControllerCore PUBLIC "-framework Security" "-framework CoreFoundation" "-framework IOKit")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSECRET REQUIRED IMPORTED_TARGET libsecret-1)
    target_link_libraries(ControllerCore PUBLIC PkgConfig::LIBSECRET)
endif()

set(NOTICES
    "${relay_mbedtls_SOURCE_DIR}/LICENSE|MBEDTLS-LICENSE.txt"
    "${relay_mbedtls_SOURCE_DIR}/3rdparty/everest/README.md|MBEDTLS-EVEREST-NOTICE.txt"
    "${relay_mbedtls_SOURCE_DIR}/3rdparty/p256-m/README.md|MBEDTLS-P256M-NOTICE.txt"
    "${relay_hidapi_SOURCE_DIR}/LICENSE-bsd.txt|HIDAPI-LICENSE.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY.txt|THIRD_PARTY.txt")

if(PICO_CONTROLLER_GUI)
    find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
    find_package(Qt${QT_VERSION_MAJOR} 5.15 REQUIRED COMPONENTS Widgets)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(GUI_SOURCES ui/main.cpp ui/main_window.cpp ui/widgets.cpp ui/device_settings_panel.cpp
        ui/safe_end_panel.cpp ui/approval.cpp ui/session_monitor.cpp ui/flash_dialog.cpp icon/app.qrc)
    # Icons come from icon/make_icon.py; rerun it after changing the design.
    if(WIN32)
        list(APPEND GUI_SOURCES app.rc ui/foreground.cpp)
    elseif(APPLE)
        enable_language(OBJCXX)
        list(APPEND GUI_SOURCES ui/foreground_mac.mm)
        set_source_files_properties(icon/app.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
        list(APPEND GUI_SOURCES icon/app.icns)
    else()
        list(APPEND GUI_SOURCES ui/foreground.cpp)
    endif()
    add_executable(Esp32KeyConfirm WIN32 MACOSX_BUNDLE ${GUI_SOURCES})
    target_include_directories(Esp32KeyConfirm PRIVATE ui)
    target_compile_options(Esp32KeyConfirm PRIVATE ${WARNINGS})
    target_link_libraries(Esp32KeyConfirm PRIVATE ControllerCore Qt${QT_VERSION_MAJOR}::Widgets)
    if(WIN32)
        target_link_libraries(Esp32KeyConfirm PRIVATE wtsapi32)
        target_link_options(Esp32KeyConfirm PRIVATE /MANIFEST:EMBED /MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/app.manifest)
    elseif(APPLE)
        target_link_libraries(Esp32KeyConfirm PRIVATE "-framework AppKit")
        # An empty CFBundleIdentifier makes the out-of-process open panel
        # dismiss itself immediately, among other identity problems.
        set_target_properties(Esp32KeyConfirm PROPERTIES OUTPUT_NAME "Pico FIDO Controller"
            MACOSX_BUNDLE_GUI_IDENTIFIER "org.picofido2.controller"
            MACOSX_BUNDLE_BUNDLE_NAME "Pico FIDO Controller"
            MACOSX_BUNDLE_ICON_FILE app.icns)
    else()
        # Session-lock detection (screensaver/logind signals) needs Qt DBus.
        find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS DBus)
        target_link_libraries(Esp32KeyConfirm PRIVATE Qt${QT_VERSION_MAJOR}::DBus)
        target_compile_definitions(Esp32KeyConfirm PRIVATE PICO_SESSION_DBUS=1)
    endif()
    # Inside a macOS bundle, non-code files belong in Resources: anything else
    # in Contents/MacOS breaks code signing.
    if(APPLE)
        set(notice_dir "$<TARGET_BUNDLE_CONTENT_DIR:Esp32KeyConfirm>/Resources")
    else()
        set(notice_dir "$<TARGET_FILE_DIR:Esp32KeyConfirm>")
    endif()
    add_custom_command(TARGET Esp32KeyConfirm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${notice_dir}/LICENSES")
    # The merged firmware image (esp32s3supermini-*.bin from the ESP-IDF build)
    # that 刷写新设备 offers by default; without it the user picks a file.
    set(PICO_FIRMWARE_IMAGE "" CACHE FILEPATH "Merged ESP32-S3 image to ship with the controller")
    if(PICO_FIRMWARE_IMAGE)
        get_filename_component(image_name "${PICO_FIRMWARE_IMAGE}" NAME)
        add_custom_command(TARGET Esp32KeyConfirm POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PICO_FIRMWARE_IMAGE}" "${notice_dir}/${image_name}")
    endif()
    foreach(notice ${NOTICES})
        string(REPLACE "|" ";" pair "${notice}")
        list(GET pair 0 from)
        list(GET pair 1 to)
        add_custom_command(TARGET Esp32KeyConfirm POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${from}" "${notice_dir}/LICENSES/${to}")
    endforeach()
endif()

# The CLI-only build works without Qt (servers, scripts and tests).
add_executable(pico-fido-cli cli_main.cpp)
target_compile_options(pico-fido-cli PRIVATE ${WARNINGS})
target_link_libraries(pico-fido-cli PRIVATE ControllerCore)

include(CTest)
if(BUILD_TESTING)
    if(PICO_CONTROLLER_GUI)
        add_executable(FormDialogTests ui/form_dialog_test.cpp ui/widgets.cpp)
        target_link_libraries(FormDialogTests PRIVATE ControllerCore Qt${QT_VERSION_MAJOR}::Widgets)
        target_compile_options(FormDialogTests PRIVATE ${WARNINGS})
        add_test(NAME controller-input-forms COMMAND FormDialogTests)
        set_tests_properties(controller-input-forms PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 15)
    endif()
    function(core_test name)
        add_executable(${name} ${ARGN})
        target_compile_options(${name} PRIVATE ${WARNINGS})
        target_link_libraries(${name} PRIVATE ControllerCore)
    endfunction()
    core_test(CredentialTests credentials_test.cpp)
    add_test(NAME credential-management COMMAND CredentialTests)
    add_test(NAME controller-crypto COMMAND pico-fido-cli --self-test)
    core_test(DeviceNameTests device_names_test.cpp)
    add_test(NAME device-names COMMAND DeviceNameTests)
    core_test(RelayConfigTests relay_config_test.cpp)
    add_test(NAME relay-configuration-codec COMMAND RelayConfigTests)
    core_test(RelaySetupTests relay_setup_test.cpp)
    add_test(NAME relay-setup-authorization COMMAND RelaySetupTests)
    core_test(RelayControlTests relay_control_test.cpp)
    add_test(NAME relay-hid-control COMMAND RelayControlTests)
    core_test(DeviceRestartTests device_restart_test.cpp)
    add_test(NAME device-authenticated-restart COMMAND DeviceRestartTests)
    core_test(RelaySettingsTests relay_settings_test.cpp)
    add_test(NAME relay-settings-storage COMMAND RelaySettingsTests)
    core_test(RelayPasswordTests relay_password_test.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../../src/fido2/relay_password.c)
    target_compile_definitions(RelayPasswordTests PRIVATE ESP_PLATFORM=1 ENABLE_REMOTE_PRESENCE=1)
    target_include_directories(RelayPasswordTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/fido2
        ${CMAKE_CURRENT_SOURCE_DIR}/../../pico-keys-sdk/src ${CMAKE_CURRENT_SOURCE_DIR}/../../pico-keys-sdk/src/rng)
    add_test(NAME relay-password-token COMMAND RelayPasswordTests)
    core_test(RelayTransportTests relay_transport_test.cpp)
    add_test(NAME relay-transport-codec COMMAND RelayTransportTests)
    core_test(RelayAuthenticatorTests relay_authenticator_test.cpp)
    add_test(NAME relay-authenticator COMMAND RelayAuthenticatorTests)
    core_test(RelayBackupTests relay_backup_test.cpp)
    add_test(NAME relay-backup-storage COMMAND RelayBackupTests)
    core_test(RelayLocalClearTests relay_local_clear_test.cpp)
    add_test(NAME relay-local-clear COMMAND RelayLocalClearTests)
    set_tests_properties(relay-local-clear PROPERTIES TIMEOUT 45)
    core_test(RelayCloudTests relay_cloud_test.cpp)
    add_test(NAME relay-cloud-native COMMAND RelayCloudTests)
    add_test(NAME relay-cloud-remembered-code COMMAND RelayCloudTests --remembered-code-tests)
    set_tests_properties(relay-cloud-remembered-code PROPERTIES TIMEOUT 45)
    set_tests_properties(relay-cloud-native PROPERTIES TIMEOUT 45)
    core_test(RelayNetworkTests relay_network_test.cpp)
    add_test(NAME relay-network COMMAND RelayNetworkTests)
    set_tests_properties(relay-network PROPERTIES TIMEOUT 45)
    core_test(RelayIdentityTests relay_identity_test.cpp)
    add_test(NAME relay-identity COMMAND RelayIdentityTests)
    set_tests_properties(relay-identity PROPERTIES TIMEOUT 30)
    core_test(SafeEndSessionTests safe_end_session_test.cpp)
    add_test(NAME safe-end-session COMMAND SafeEndSessionTests)
    set_tests_properties(safe-end-session PROPERTIES TIMEOUT 30)
    core_test(RelayPinInterop relay_pin_interop.cpp)
    # zlib stands in for the ESP32-S3 ROM's inflater.
    find_package(ZLIB)
    if(ZLIB_FOUND)
        core_test(EspFlasherTests esp_flasher_test.cpp)
        target_link_libraries(EspFlasherTests PRIVATE ZLIB::ZLIB)
        add_test(NAME esp-flasher COMMAND EspFlasherTests)
        set_tests_properties(esp-flasher PROPERTIES TIMEOUT 60)
    endif()

    # Firmware sources compiled on the host against small platform fixtures.
    add_executable(EspRandomTests esp_random_test.cpp ${SDK}/src/rng/esp_random_source.c ${SDK}/src/rng/random.c ${SDK}/src/rng/hwrng.c)
    target_compile_definitions(EspRandomTests PRIVATE ESP_PLATFORM=1)
    target_include_directories(EspRandomTests PRIVATE esp-rng-stubs ${SDK}/src/rng)
    target_compile_options(EspRandomTests PRIVATE ${WARNINGS})
    target_link_libraries(EspRandomTests PRIVATE ControllerCore)
    add_test(NAME esp-power-safe-random COMMAND EspRandomTests)

    # The lwIP socket shim maps onto Winsock; this fixture is Windows-only.
    if(WIN32)
        add_library(RelayEspNetwork STATIC ../../src/fido2/relay_network.c)
        target_compile_definitions(RelayEspNetwork PRIVATE ESP_PLATFORM=1 ENABLE_REMOTE_PRESENCE=1)
        target_include_directories(RelayEspNetwork PRIVATE relay-network-stubs ${SHARED} ../../src/fido2 ${SDK}/src/rng)
        target_compile_options(RelayEspNetwork PRIVATE ${WARNINGS})
        force_include(RelayEspNetwork ${CMAKE_CURRENT_SOURCE_DIR}/relay-network-stubs/heap.h)
        target_link_libraries(RelayEspNetwork PRIVATE RelayConfig mbedtls mbedx509 mbedcrypto)
        core_test(RelayEspNetworkTests relay_esp_network_test.cpp)
        target_link_libraries(RelayEspNetworkTests PRIVATE RelayEspNetwork)
        add_test(NAME relay-esp-network COMMAND RelayEspNetworkTests)
        set_tests_properties(relay-esp-network PROPERTIES TIMEOUT 60)
    endif()

    add_executable(RelayDispatchTests relay_dispatch_test.cpp ${SDK}/src/apdu.c ${SDK}/src/usb/hid/hid.c ../../pico-fido/src/fido/cbor.c
        ${SDK}/src/fs/file.c ${SDK}/src/asn1.c
        ${SDK}/tinycbor/src/cborencoder.c ${SDK}/tinycbor/src/cborparser.c ${SDK}/tinycbor/src/cborparser_dup_string.c)
    target_compile_definitions(RelayDispatchTests PRIVATE ESP_PLATFORM=1 ENABLE_REMOTE_PRESENCE=1 USB_ITF_HID=1 USB_ITF_CCID=1 ENABLE_OATH_APP=1)
    target_include_directories(RelayDispatchTests PRIVATE relay-dispatch-stubs ${SDK}/src ${SDK}/src/fs ${SDK}/src/usb ${SDK}/tinycbor/src)
    target_compile_options(RelayDispatchTests PRIVATE ${WARNINGS})
    force_include(RelayDispatchTests ${CMAKE_CURRENT_SOURCE_DIR}/relay-dispatch-stubs/platform.h)
    target_link_libraries(RelayDispatchTests PRIVATE mbedcrypto)
    add_test(NAME relay-dispatch-isolation COMMAND RelayDispatchTests)

    add_executable(RelayFirmwareTests relay_firmware_test.cpp ../../src/fido2/relay_firmware.c
        ../../src/fido2/relay_password.c
        ${SDK}/tinycbor/src/cborparser.c ${SDK}/src/led/led.c)
    target_compile_definitions(RelayFirmwareTests PRIVATE ESP_PLATFORM=1 ENABLE_REMOTE_PRESENCE=1 LED_ACTIVITY_ONLY=1)
    target_include_directories(RelayFirmwareTests PRIVATE relay-firmware-stubs ../../src/fido2 ${SDK} ${SDK}/src ${SDK}/tinycbor/src ${SDK}/src/rng)
    target_compile_options(RelayFirmwareTests PRIVATE ${WARNINGS})
    target_link_libraries(RelayFirmwareTests PRIVATE ControllerCore)
    add_test(NAME relay-firmware-storage COMMAND RelayFirmwareTests)
    set_tests_properties(relay-firmware-storage PROPERTIES TIMEOUT 90)

    add_executable(EspOtpTests esp_otp_test.cpp ${SDK}/src/fs/otp.c ${SDK}/src/fs/esp_otp_read.c)
    target_compile_definitions(EspOtpTests PRIVATE ESP_PLATFORM=1 PICO_NO_EFUSE_KEYS=1 _FILE_H_=1)
    target_include_directories(EspOtpTests PRIVATE esp-otp-stubs ${SDK}/src/fs ${SDK}/src/rng)
    target_compile_options(EspOtpTests PRIVATE ${WARNINGS})
    target_link_libraries(EspOtpTests PRIVATE mbedcrypto)
    add_test(NAME esp-existing-storage-keys COMMAND EspOtpTests)

    set(RELAY_TEST_PYTHON "" CACHE FILEPATH "Optional Python with tools/requirements-test.txt for independent PIN/backup interoperability checks")
    if(RELAY_TEST_PYTHON)
        add_test(NAME relay-pin-interop COMMAND "${RELAY_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/../check_relay_pin.py" "$<TARGET_FILE:RelayPinInterop>")
        set_tests_properties(relay-pin-interop PROPERTIES TIMEOUT 180)
        add_test(NAME relay-backup-interop COMMAND "${RELAY_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/../check_relay_backup.py" "$<TARGET_FILE:RelayPinInterop>")
        set_tests_properties(relay-backup-interop PROPERTIES TIMEOUT 120)
        if(WIN32)
            add_test(NAME relay-backup-console COMMAND "${RELAY_TEST_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/../check_relay_console.py" "$<TARGET_FILE:pico-fido-cli>" "$<TARGET_FILE:RelayCloudTests>")
            set_tests_properties(relay-backup-console PROPERTIES TIMEOUT 45)
        endif()
    endif()
endif()

# macOS login-keychain items are partitioned by code signature. Ad-hoc builds are
# identified by their cdhash, so each rebuilt executable would hit an access
# prompt; signing everything with one identity shares the "teamid:" partition.
if(APPLE)
    set(PICO_MACOS_CODESIGN_IDENTITY "" CACHE STRING "codesign identity for all executables, e.g. \"Apple Development: ...\"")
    if(PICO_MACOS_CODESIGN_IDENTITY)
        get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
        foreach(target ${targets})
            get_target_property(type ${target} TYPE)
            if(type STREQUAL "EXECUTABLE")
                get_target_property(bundle ${target} MACOSX_BUNDLE)
                if(bundle)
                    set(signed "$<TARGET_BUNDLE_DIR:${target}>")
                else()
                    set(signed "$<TARGET_FILE:${target}>")
                endif()
                add_custom_command(TARGET ${target} POST_BUILD
                    COMMAND codesign --force --timestamp=none --sign "${PICO_MACOS_CODESIGN_IDENTITY}" "${signed}" VERBATIM)
            endif()
        endforeach()
    endif()
endif()
