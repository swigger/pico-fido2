#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE)
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "remote_presence.h"
#include "relay_hid.h"
#include "relay_firmware.h"
#include "relay_network.h"
#include "device_restart.h"
#include "relay_diagnostics.h"
#include "../../shared/relay_diagnostics.h"
#include "esp_system.h"
#include "relay_password.h"
#include "relay_transport.h"
#include "usb.h"
#include "driver/gpio.h"
#include "pico_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "cbor.h"

static relay_hid_t setup;
static relay_config_t boot_config;
// Decoded form of the last saved blob: it may contain sealed tokens and is the
// source for GET 19. boot_config is always the resolved plaintext runtime copy.
static relay_config_t stored_config;
static nvs_handle_t storage;
static bool storage_ready;
static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static bool boot_ready, runtime_fault = true, setup_active;
static uint8_t runtime_mode;
static uint8_t snapshots[3][63];
static device_restart_t restart;
static uint8_t restart_snapshot[63];
// TinyUSB callbacks only enqueue/copy; never run crypto or flash IO there.
static struct { uint8_t report, bytes[63]; } queue[8];
static unsigned queue_head, queue_count;
static bool queue_overflow;
static uint8_t discovery_blob[65], discovery_config[32];
static uint64_t discovery_generation;
static bool discovery_pin, discovery_dirty;

void relay_firmware_discovery(const uint8_t metadata[25]) {
    if (!metadata || metadata[24] > 1) return;
    uint64_t generation = 0;
    for (unsigned i = 0; i < 8; ++i) generation |= (uint64_t)metadata[16 + i] << (8 * i);
    if (!generation) return;
    portENTER_CRITICAL(&lock);
    bool same_vault = !memcmp(discovery_blob, "PF2INF01", 8) && !memcmp(discovery_blob + 40, metadata, 16);
    if (same_vault && generation < discovery_generation) { portEXIT_CRITICAL(&lock); return; }
    discovery_generation = generation;
    if (memcmp(discovery_blob + 40, metadata, 16) || discovery_blob[56] != metadata[24] ||
        memcmp(discovery_blob, "PF2INF01", 8)) {
        memcpy(discovery_blob, "PF2INF01", 8);
        memcpy(discovery_blob + 8, discovery_config, 32);
        memcpy(discovery_blob + 40, metadata, 16); discovery_blob[56] = metadata[24];
        memcpy(discovery_blob + 57, metadata + 16, 8);
        discovery_pin = metadata[24] != 0; discovery_dirty = true;
    }
    portEXIT_CRITICAL(&lock);
}
static void discovery_load(void) {
    memcpy(discovery_config, setup.stored_digest, 32);
    size_t size = sizeof(discovery_blob);
    if (nvs_get_blob(storage, "info_v1", discovery_blob, &size) == ESP_OK && size == sizeof(discovery_blob) &&
        !memcmp(discovery_blob, "PF2INF01", 8) && !memcmp(discovery_blob + 8, discovery_config, 32) && discovery_blob[56] <= 1) {
        discovery_pin = discovery_blob[56] != 0;
        for (unsigned i = 0; i < 8; ++i) discovery_generation |= (uint64_t)discovery_blob[57 + i] << (8 * i);
    } else memset(discovery_blob, 0, sizeof(discovery_blob));
}
static void discovery_save(void) {
    uint8_t blob[sizeof(discovery_blob)]; bool dirty;
    portENTER_CRITICAL(&lock);
    dirty = discovery_dirty; discovery_dirty = false; memcpy(blob, discovery_blob, sizeof(blob));
    portEXIT_CRITICAL(&lock);
    // Cache loss is harmless: actual operations always revalidate remotely.
    // Persist only a changed vault/PIN hint, never every request/generation.
    if (dirty && storage_ready && nvs_set_blob(storage, "info_v1", blob, sizeof(blob)) == ESP_OK) (void)nvs_commit(storage);
}
static int discovery_info(uint8_t *response, size_t capacity, uint16_t *length) {
    static const uint8_t prefix[] = {0xa5, 1, 0x81, 0x68, 'F','I','D','O','_','2','_','0',
        3, 0x50, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        4, 0xa5, 0x62,'r','k',0xf5, 0x62,'u','p',0xf5, 0x64,'p','l','a','t',0xf4,
        0x69,'c','l','i','e','n','t','P','i','n'};
    static const uint8_t suffix[] = {0x6e,'p','i','n','U','v','A','u','t','h','T','o','k','e','n',0xf5,
        5,0x19,(uint8_t)(RELAY_CTAP_MAX >> 8),(uint8_t)(RELAY_CTAP_MAX & 0xff), 6,0x82,2,1};
    size_t size = sizeof(prefix) + 1 + sizeof(suffix);
    if (capacity < size) return 0x03;
    portENTER_CRITICAL(&lock); bool pin = discovery_pin; portEXIT_CRITICAL(&lock);
    memcpy(response, prefix, sizeof(prefix)); response[sizeof(prefix)] = pin ? 0xf5 : 0xf4;
    memcpy(response + sizeof(prefix) + 1, suffix, sizeof(suffix)); *length = (uint16_t)size; return 0;
}

static bool setup_random(void *user, uint8_t nonce[32]) {
    (void)user;
    picok_random_fill(nonce, 32);
    return true;
}
static bool restart_random(uint8_t nonce[32]) { return setup_random(NULL, nonce); }
static bool restart_verify(const uint8_t id[16], const uint8_t *message, size_t length, const uint8_t signature[64]) {
    uint8_t digest[32];
    return !mbedtls_sha256(message, length, digest, 0) && remote_presence_verify_digest(id, digest, signature);
}
static bool setup_verify(void *user, const uint8_t id[16], const uint8_t *context, size_t context_len,
                          const uint8_t *wire, size_t wire_len, const uint8_t signature[64],
                          const relay_config_t *config) {
    (void)user;
    uint8_t digest[32];
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int err = mbedtls_sha256_starts(&hash, 0);
    if (!err) err = mbedtls_sha256_update(&hash, context, context_len);
    if (!err) err = mbedtls_sha256_update(&hash, wire, wire_len);
    if (!err) err = mbedtls_sha256_finish(&hash, digest);
    mbedtls_sha256_free(&hash);
    return !err && remote_presence_verify_digest(id, digest, signature) &&
        relay_password_config_valid(config, (const uint8_t *)pico_serial_str);
}
static void fault(void) {
    portENTER_CRITICAL(&lock);
    runtime_fault = true;
    relay_hid_publish_config(&setup, NULL, 0);
    portEXIT_CRITICAL(&lock);
    setup.flags |= RELAY_HID_BOOT_FAULT;
}
static void clear_read_config(void) {
    portENTER_CRITICAL(&lock);
    relay_hid_publish_config(&setup, NULL, 0);
    portEXIT_CRITICAL(&lock);
}
// Build the sealed view returned by GET 19. Plaintext entries are sealed here,
// on the application task; existing tokens are preserved. A failure leaves the
// read channel unavailable but does not invalidate the stored configuration.
static bool publish_read_config(void) {
    for (unsigned i = 0; i < stored_config.network_count; ++i) {
        relay_network_t *network = &stored_config.networks[i];
        if (!network->password_length ||
            relay_config_password_token(network->password, network->password_length)) continue;
        char token[RELAY_MAX_PASSWORD];
        size_t length = 0;
        bool ok = relay_password_seal((const uint8_t *)pico_serial_str, network->password,
                                      network->password_length, token, sizeof(token), &length);
        if (!ok) {
            mbedtls_platform_zeroize(token, sizeof(token));
            clear_read_config();
            return false;
        }
        mbedtls_platform_zeroize(network->password, sizeof(network->password));
        memcpy(network->password, token, length);
        network->password_length = (uint8_t)length;
        mbedtls_platform_zeroize(token, sizeof(token));
    }
    size_t length = 0;
    if (relay_config_encode(&stored_config, setup.setup.wire, sizeof(setup.setup.wire), &length) != RELAY_CONFIG_OK) {
        clear_read_config();
        return false;
    }
    portENTER_CRITICAL(&lock);
    relay_hid_publish_config(&setup, setup.setup.wire, length);
    portEXIT_CRITICAL(&lock);
    mbedtls_platform_zeroize(setup.setup.wire, length);
    return true;
}
static bool setup_persist(void *user, const uint8_t *wire, size_t length) {
    (void)user;
    if (!storage_ready) return false;
    uint8_t *readback = malloc(length);
    if (!readback) return false;
    // Missing/corrupt configuration after initialization must never look like a
    // pristine local-only device. Store the marker before the first blob.
    esp_err_t err = nvs_set_u8(storage, "initialized", 1);
    if (err == ESP_OK) err = nvs_commit(storage);
    if (err == ESP_OK) err = nvs_set_blob(storage, "config_v1", wire, length);
    if (err == ESP_OK) err = nvs_commit(storage);
    size_t n = length;
    if (err == ESP_OK) err = nvs_get_blob(storage, "config_v1", readback, &n);
    bool ok = err == ESP_OK && n == length && !memcmp(readback, wire, length);
    mbedtls_platform_zeroize(readback, length);
    free(readback);
    if (!ok) {
        // An IO failure can leave the new blob committed. Do not serve local
        // credentials in an uncertain state or claim the update succeeded.
        fault();
        return false;
    }
    setup.stored_mode = (uint8_t)setup.setup.decoded.mode;
    setup.stored_networks = setup.setup.decoded.network_count;
    mbedtls_sha256(wire, length, setup.stored_digest, 0);
    setup.flags |= RELAY_HID_REBOOT_REQUIRED;
    // Keep the exact submitted wire as device authority; GET 19 serves its
    // sealed view. If sealing fails, reads fail closed instead of returning the
    // previous configuration.
    stored_config = setup.setup.decoded;
    (void)publish_read_config();
    return true;
}
static void publish(void) {
    uint8_t reports[3][63];
    uint32_t now = board_millis();
    for (unsigned i = 0; i < 3; ++i) relay_hid_get(&setup, (uint8_t)(16 + i), reports[i], now);
    // Versioned read-only extension in the previously reserved status tail.
    memcpy(reports[0] + 42, "NET1", 4);
    relay_network_diagnostics(reports[0] + 46);
    memcpy(reports[0] + 50, "MGT1", 4); reports[0][54] = 1;
#ifdef ENABLE_RELAY_DIAGNOSTICS
    reports[0][54] |= 2;
#endif
    uint8_t restart_report[63]; device_restart_get(&restart, restart_report);
    portENTER_CRITICAL(&lock);
    memcpy(snapshots, reports, sizeof(reports));
    memcpy(restart_snapshot, restart_report, 63);
    setup_active = relay_setup_active(&setup.setup);
    portEXIT_CRITICAL(&lock);
}
void remote_device_init(void) {
    relay_network_init();
    device_restart_init(&restart, (const uint8_t *)pico_serial_str, restart_random, restart_verify);
    relay_setup_callbacks_t callbacks = {NULL, setup_random, setup_verify, setup_persist};
    relay_hid_init(&setup, (const uint8_t *)pico_serial_str, callbacks);
    bool valid = false;
    if (nvs_flash_init() == ESP_OK && nvs_open("fido_relay", NVS_READWRITE, &storage) == ESP_OK) {
        storage_ready = true;
        setup.flags |= RELAY_HID_STORAGE_READY;
        uint8_t initialized = 0;
        esp_err_t marker = nvs_get_u8(storage, "initialized", &initialized);
        size_t n = 0;
        esp_err_t found = nvs_get_blob(storage, "config_v1", NULL, &n);
        if (marker == ESP_ERR_NVS_NOT_FOUND && found == ESP_ERR_NVS_NOT_FOUND) {
            valid = true;
        } else if (marker == ESP_OK && initialized == 1 && found == ESP_OK &&
                   n >= RELAY_CONFIG_HEADER_SIZE && n <= RELAY_CONFIG_MAX_SIZE) {
            uint8_t *wire = malloc(n);
            size_t length = n;
            if (wire) {
                valid = nvs_get_blob(storage, "config_v1", wire, &length) == ESP_OK && length == n &&
                    relay_config_decode(wire, n, &boot_config) == RELAY_CONFIG_OK;
                if (valid) mbedtls_sha256(wire, n, setup.stored_digest, 0);
                mbedtls_platform_zeroize(wire, n);
                free(wire);
            }
        }
    }
    if (valid) {
        stored_config = boot_config;
        if (!relay_password_resolve_config(&boot_config, (const uint8_t *)pico_serial_str)) valid = false;
    }
    if (valid) {
        setup.flags &= (uint8_t)~RELAY_HID_BOOT_FAULT;
        setup.running_mode = setup.stored_mode = (uint8_t)boot_config.mode;
        setup.running_networks = setup.stored_networks = boot_config.network_count;
        (void)publish_read_config();
    } else {
        relay_config_clear(&boot_config);
        relay_config_clear(&stored_config);
        clear_read_config();
    }
    portENTER_CRITICAL(&lock);
    runtime_fault = !valid;
    runtime_mode = (uint8_t)boot_config.mode;
    boot_ready = true;
    portEXIT_CRITICAL(&lock);
    if (valid && boot_config.mode == RELAY_MODE_RELAY) {
        discovery_load(); relay_network_start_background(&boot_config);
    }
    relay_diagnostics_init();
    publish();
}
bool remote_device_local_allowed(void) {
    portENTER_CRITICAL(&lock);
    bool allowed = boot_ready && !runtime_fault && runtime_mode == RELAY_MODE_LOCAL;
    portEXIT_CRITICAL(&lock);
    return allowed;
}
const relay_config_t *relay_firmware_config(void) {
    portENTER_CRITICAL(&lock);
    bool allowed = boot_ready && !runtime_fault && runtime_mode == RELAY_MODE_RELAY;
    portEXIT_CRITICAL(&lock);
    return allowed ? &boot_config : NULL;
}
bool remote_device_setup_active(void) {
    portENTER_CRITICAL(&lock);
    bool active = setup_active;
    portEXIT_CRITICAL(&lock);
    return active;
}
uint16_t remote_device_get(uint8_t report, uint8_t *buffer, uint16_t length) {
    if (length < 63) return 0;
#ifdef ENABLE_RELAY_DIAGNOSTICS
    if (report == RELAY_DIAGNOSTIC_REPORT) return relay_diagnostics_get(buffer) ? 63 : 0;
#endif
    if (report == DEVICE_RESTART_REPORT) {
        portENTER_CRITICAL(&lock); memcpy(buffer, restart_snapshot, 63); portEXIT_CRITICAL(&lock); return 63;
    }
    if (report == RELAY_HID_READ) {
        portENTER_CRITICAL(&lock);
        bool ok = relay_hid_get(&setup, report, buffer, board_millis());
        portEXIT_CRITICAL(&lock);
        return ok ? 63 : 0;
    }
    if (report < 16 || report > 18) return 0;
    portENTER_CRITICAL(&lock);
    memcpy(buffer, snapshots[report - 16], 63);
    portEXIT_CRITICAL(&lock);
    return 63;
}
void remote_device_set(uint8_t report, const uint8_t *buffer, uint16_t length) {
    bool allowed = (report >= 16 && report <= 19) || report == DEVICE_RESTART_REPORT || report == DEVICE_RESTART_SIGNATURE_REPORT;
#ifdef ENABLE_RELAY_DIAGNOSTICS
    allowed |= report == RELAY_DIAGNOSTIC_REPORT;
#endif
    if (!allowed || length != 63) return;
    portENTER_CRITICAL(&lock);
    if (queue_count == 8) queue_overflow = true;
    else {
        unsigned tail = (queue_head + queue_count++) % 8;
        queue[tail].report = report;
        memcpy(queue[tail].bytes, buffer, 63);
    }
    portEXIT_CRITICAL(&lock);
}
void remote_device_service(void) {
    if (!boot_ready) return;
    discovery_save();
    bool overflow;
    portENTER_CRITICAL(&lock);
    overflow = queue_overflow;
    if (overflow) {
        queue_overflow = false;
        memset(queue, 0, sizeof(queue));
        queue_head = queue_count = 0;
    }
    portEXIT_CRITICAL(&lock);
    if (overflow) {
        relay_setup_cancel(&setup.setup, setup.setup.transaction);
        setup.command_result = RELAY_HID_BAD_SEQUENCE;
        device_restart_init(&restart, (const uint8_t *)pico_serial_str, restart_random, restart_verify);
    }
    bool busy = is_busy() || remote_presence_pairing();
    for (unsigned i = 0; !overflow && i < 8; ++i) {
        uint8_t report = 0, bytes[63];
        portENTER_CRITICAL(&lock);
        if (queue_count) {
            report = queue[queue_head].report;
            memcpy(bytes, queue[queue_head].bytes, 63);
            memset(&queue[queue_head], 0, sizeof(queue[queue_head]));
            queue_head = (queue_head + 1) % 8;
            --queue_count;
        }
        portEXIT_CRITICAL(&lock);
        if (!report) break;
#ifdef ENABLE_RELAY_DIAGNOSTICS
        if (report == RELAY_DIAGNOSTIC_REPORT) { relay_diagnostics_select(bytes); continue; }
#endif
        if (report == DEVICE_RESTART_REPORT || report == DEVICE_RESTART_SIGNATURE_REPORT) {
            device_restart_set(&restart, report, bytes, board_millis(), busy || relay_setup_active(&setup.setup));
        } else if (restart.phase == DEVICE_RESTART_ACCEPTED) {
            setup.command_result = RELAY_HID_BAD_STATE;
        } else if (report == 16 && bytes[0] == RELAY_HID_READ_REQUEST) {
            portENTER_CRITICAL(&lock);
            relay_hid_set(&setup, report, bytes, board_millis(), busy);
            portEXIT_CRITICAL(&lock);
        } else relay_hid_set(&setup, report, bytes, board_millis(), busy);
        mbedtls_platform_zeroize(bytes, sizeof(bytes));
    }
    relay_hid_poll(&setup, board_millis(), busy, gpio_get_level(GPIO_NUM_0) == 0);
    relay_diagnostics_poll();
    publish();
    if (device_restart_poll(&restart, board_millis(), is_busy() || remote_presence_pairing() || relay_setup_active(&setup.setup))) {
        remote_device_trace(RELAY_DIAG_RESTART, 1, 0);
        esp_restart();
    }
}
// Recognize only a complete, definite CTAP map with unique ascending integer
// keys. Malformed/noncanonical input stays on the normal validation path.
static bool ctap_field(const uint8_t *data, size_t length, uint64_t key, CborParser *parser, CborValue *field) {
    CborValue root, it;
    size_t count;
    if (!data || !length || cbor_parser_init(data, length, 0, parser, &root) ||
        !cbor_value_is_map(&root) || cbor_value_get_map_length(&root, &count) || count > 64 ||
        cbor_value_enter_container(&root, &it)) return false;
    bool found = false, have_previous = false;
    uint64_t previous = 0;
    while (!cbor_value_at_end(&it)) {
        uint64_t current;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &current) ||
            (have_previous && current <= previous) || cbor_value_advance(&it)) return false;
        previous = current; have_previous = true;
        if (current == key) { *field = it; found = true; }
        if (cbor_value_advance(&it)) return false;
    }
    return !cbor_value_leave_container(&root, &it) && cbor_value_get_next_byte(&root) == data + length && found;
}
static bool selection_probe(const uint8_t *data, size_t length) {
    if (length < 2 || (data[0] != 1 && data[0] != 2)) return false;
    CborParser parser;
    CborValue auth;
    size_t size;
    return ctap_field(data + 1, length - 1, data[0] == 1 ? 8 : 6, &parser, &auth) &&
        cbor_value_is_byte_string(&auth) && !cbor_value_get_string_length(&auth, &size) && size == 0;
}
static int device_cbor(uint8_t command, const uint8_t *data, size_t length,
                       uint8_t *response, size_t capacity, uint16_t *response_length) {
    *response_length = 0;
    if (!relay_firmware_config()) return 0x7f;
    if (command != 0x90) return 0x01;
    if (!data || !length) return 0x03;
    if (data[0] == 4) return length == 1 ? discovery_info(response, capacity, response_length) : 0x03;
    if (data[0] == 0x0a || data[0] == 0x41) return 0x2e;
    // Forward only what the safe end implements; reset/config/largeBlobs/bio and
    // other vendor commands never leave the device.
    if (data[0] != 0x01 && data[0] != 0x02 && data[0] != 0x04 && data[0] != 0x06 &&
        data[0] != 0x08 && data[0] != RELAY_CTAP_EXACT_QUERY) return 0x01;
    if (selection_probe(data, length)) {
        // A selection hint never contacts Wi-Fi/cloud or grants UP/UV. The safe
        // end validates its latest PIN state before any real operation succeeds.
        portENTER_CRITICAL(&lock); bool configured = discovery_pin; portEXIT_CRITICAL(&lock);
        mbedtls_platform_zeroize(response, capacity); *response_length = 0;
        return configured ? 0x31 : 0x35;
    }
    return relay_network_exchange(relay_firmware_config(), data, length, response, capacity, response_length);
}
int remote_device_cbor(uint8_t command, const uint8_t *data, size_t length,
                       uint8_t *response, size_t capacity, uint16_t *response_length) {
    remote_device_trace(RELAY_DIAG_CTAP, data && length ? data[0] : 0xff, (uint16_t)length);
    int result = device_cbor(command, data, length, response, capacity, response_length);
    remote_device_trace(RELAY_DIAG_RESULT, (uint8_t)result, *response_length);
    return result;
}
uint8_t remote_device_keepalive(void) { return relay_network_keepalive(); }
#endif
