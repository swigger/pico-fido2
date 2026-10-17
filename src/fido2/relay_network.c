#if defined(ESP_PLATFORM) && defined(ENABLE_REMOTE_PRESENCE)
#include "relay_network.h"
#include "relay_firmware.h"
#include "relay_transport.h"
#include "remote_presence.h"
#include "pico_keys.h"
#include "tusb.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "pico_random.h"
#include "esp_pm.h"
#include "nvs.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"
#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#error "Relay requires TLS client, ECDHE-ECDSA and the kept peer certificate; use sdkconfig.relay.defaults"
#endif

extern bool cancel_button;
static bool wifi_ready;
static bool wifi_attempted;
static int network_index = -1;
static bool has_ip;
static bool has_ipv6;
static esp_netif_t *station;
static uint8_t keepalive = 1;
static unsigned first_profile;
static uint8_t boot_id[16];
static bool boot_id_ready;
static uint8_t diagnostic_phase, wifi_reason, diagnostic_profile;
static bool associated;
static bool wifi_connecting, wifi_failed, wifi_canceling, wifi_succeeded;
static uint32_t wifi_started;
// A preference is an optional cache, never authority for configuration or trust.
static bool preference_loaded, preference_storage;
static nvs_handle_t preference_handle;
static uint8_t preference_record[44];
static int saved_profile = -1;
static SemaphoreHandle_t network_mutex;
static bool foreground_waiting, background_active;
void relay_network_init(void) {
    // Keep APB at 80 MHz and USB awake; only scale CPU and use Wi-Fi modem sleep.
    esp_pm_config_t pm = {.max_freq_mhz = 160, .min_freq_mhz = 80, .light_sleep_enable = false};
    ESP_ERROR_CHECK(esp_pm_configure(&pm));
    network_mutex = xSemaphoreCreateMutex();
}
static void phase(uint8_t value) { __atomic_store_n(&diagnostic_phase, value, __ATOMIC_RELEASE); }
void relay_network_diagnostics(uint8_t out[4]) {
    out[0] = __atomic_load_n(&diagnostic_phase, __ATOMIC_ACQUIRE);
    out[1] = __atomic_load_n(&wifi_reason, __ATOMIC_ACQUIRE);
    out[2] = (__atomic_load_n(&wifi_ready, __ATOMIC_ACQUIRE) ? 1 : 0) |
        (__atomic_load_n(&associated, __ATOMIC_ACQUIRE) ? 2 : 0) |
        (__atomic_load_n(&has_ip, __ATOMIC_ACQUIRE) ? 4 : 0) |
        (__atomic_load_n(&has_ipv6, __ATOMIC_ACQUIRE) ? 8 : 0);
    out[3] = __atomic_load_n(&diagnostic_profile, __ATOMIC_ACQUIRE);
}
uint8_t relay_network_keepalive(void) { return __atomic_load_n(&keepalive, __ATOMIC_ACQUIRE); }
static void status(uint8_t value) { __atomic_store_n(&keepalive, value, __ATOMIC_RELEASE); }
static bool canceled(void) {
    return __atomic_load_n(&cancel_button, __ATOMIC_ACQUIRE) || !tud_mounted() || tud_suspended() ||
        (background_active && __atomic_load_n(&foreground_waiting, __ATOMIC_ACQUIRE));
}
typedef struct { uint32_t start, limit; } deadline_t;
static bool live(deadline_t deadline) { return !canceled() && (uint32_t)(board_millis() - deadline.start) < deadline.limit; }
static void pause_io(void) { vTaskDelay(pdMS_TO_TICKS(5) ? pdMS_TO_TICKS(5) : 1); }
static bool joining(void) { return __atomic_load_n(&wifi_connecting, __ATOMIC_ACQUIRE); }
static bool linked(void) { return __atomic_load_n(&associated, __ATOMIC_ACQUIRE); }
static void load_preference(const relay_config_t *settings) {
    if (preference_loaded) return;
    preference_loaded = true;
    uint8_t *wire = calloc(1, RELAY_CONFIG_MAX_SIZE); size_t length = 0;
    if (!wire) return;
    bool ok = relay_config_encode(settings, wire, RELAY_CONFIG_MAX_SIZE, &length) == RELAY_CONFIG_OK &&
        !mbedtls_sha256(wire, length, preference_record + 12, 0);
    mbedtls_platform_zeroize(wire, RELAY_CONFIG_MAX_SIZE); free(wire);
    if (!ok) return;
    memcpy(preference_record, "PF2WIFI1", 8); preference_record[9] = settings->network_count;
    if (nvs_open("fido_net", NVS_READWRITE, &preference_handle) != ESP_OK) return;
    preference_storage = true;
    uint8_t stored[44]; length = sizeof(stored);
    if (nvs_get_blob(preference_handle, "last_wifi_v1", stored, &length) == ESP_OK && length == sizeof(stored) &&
        !memcmp(stored, preference_record, 8) && !memcmp(stored + 9, preference_record + 9, 35) &&
        stored[8] < settings->network_count) {
        first_profile = stored[8]; saved_profile = stored[8];
    }
}
static void remember_wifi(unsigned index) {
    first_profile = index;
    if (!preference_storage || saved_profile == (int)index) return;
    preference_record[8] = (uint8_t)index;
    if (nvs_set_blob(preference_handle, "last_wifi_v1", preference_record, sizeof(preference_record)) != ESP_OK ||
        nvs_commit(preference_handle) != ESP_OK) {
        preference_storage = false; // Do not repeatedly write a failing optional cache.
        return;
    }
    saved_profile = (int)index;
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *event) {
    (void)arg;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP && linked()) {
        __atomic_store_n(&has_ip, true, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_succeeded, true, __ATOMIC_RELEASE);
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) __atomic_store_n(&has_ip, false, __ATOMIC_RELEASE);
    if (base == IP_EVENT && id == IP_EVENT_GOT_IP6 && event && linked()) {
        ip_event_got_ip6_t *got = event;
        esp_ip6_addr_type_t type = esp_netif_ip6_get_addr_type(&got->ip6_info.ip);
        // A link-local address arrives before DHCP/SLAAC completes. It does not
        // establish DNS or endpoint reachability and must not end the wait early.
        if (type == ESP_IP6_ADDR_IS_GLOBAL || type == ESP_IP6_ADDR_IS_UNIQUE_LOCAL) {
            __atomic_store_n(&has_ipv6, true, __ATOMIC_RELEASE);
            __atomic_store_n(&wifi_succeeded, true, __ATOMIC_RELEASE);
        }
    }
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        __atomic_store_n(&associated, true, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_connecting, false, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_failed, false, __ATOMIC_RELEASE);
        esp_netif_create_ip6_linklocal(station);
    }
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        __atomic_store_n(&associated, false, __ATOMIC_RELEASE);
        if (event) __atomic_store_n(&wifi_reason, ((wifi_event_sta_disconnected_t *)event)->reason, __ATOMIC_RELEASE);
        __atomic_store_n(&has_ip, false, __ATOMIC_RELEASE); __atomic_store_n(&has_ipv6, false, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_connecting, false, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_failed, true, __ATOMIC_RELEASE);
    }
}
static bool connected(void) { return __atomic_load_n(&has_ip, __ATOMIC_ACQUIRE) || __atomic_load_n(&has_ipv6, __ATOMIC_ACQUIRE); }
static bool wifi_init(void) {
    if (wifi_ready) return true;
    if (wifi_attempted) return false;
    wifi_attempted = true; // A partial driver initialization needs a reboot.
    esp_err_t err = esp_netif_init(); if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return false;
    err = esp_event_loop_create_default(); if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return false;
    station = esp_netif_create_default_wifi_sta(); if (!station) return false;
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT(); config.nvs_enable = 0;
    if (esp_wifi_init(&config) != ESP_OK || esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL) != ESP_OK ||
        esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL) != ESP_OK ||
        esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK || esp_wifi_start() != ESP_OK) return false;
    if (esp_wifi_set_ps(WIFI_PS_MIN_MODEM) != ESP_OK) return false;
    __atomic_store_n(&wifi_ready, true, __ATOMIC_RELEASE); return true;
}
static bool connect_wifi(const relay_network_t *network, unsigned index, deadline_t deadline) {
    __atomic_store_n(&diagnostic_profile, (uint8_t)(index + 1), __ATOMIC_RELEASE);
    if (!wifi_ready) phase(1);
    if (!wifi_init()) return false;
    if (network_index == (int)index && linked() && connected() && !wifi_canceling) return true;
    if (!linked() && !joining() && !wifi_canceling) {
        phase(2); __atomic_store_n(&wifi_reason, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&has_ip, false, __ATOMIC_RELEASE); __atomic_store_n(&has_ipv6, false, __ATOMIC_RELEASE);
        // Only configure when no AP is associated and no old join/cancel is in flight.
        if (network->password_length > RELAY_MAX_PASSWORD_PLAIN) return false;
        wifi_config_t config = {0}; memcpy(config.sta.ssid, network->ssid, network->ssid_length);
        memcpy(config.sta.password, network->password, network->password_length);
        config.sta.threshold.authmode = network->password_length ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &config); mbedtls_platform_zeroize(&config, sizeof(config));
        if (err != ESP_OK) return false;
        network_index = (int)index; wifi_started = board_millis();
        __atomic_store_n(&wifi_succeeded, false, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_failed, false, __ATOMIC_RELEASE);
        __atomic_store_n(&wifi_connecting, true, __ATOMIC_RELEASE);
        if (esp_wifi_connect() != ESP_OK) {
            __atomic_store_n(&wifi_connecting, false, __ATOMIC_RELEASE); return false;
        }
    }
    phase(3);
    while (live(deadline)) {
        if (__atomic_load_n(&wifi_failed, __ATOMIC_ACQUIRE)) { wifi_canceling = false; return false; }
        if (!wifi_canceling && linked() && connected()) return true;
        if (!wifi_canceling && !linked() && joining() && (uint32_t)(board_millis() - wifi_started) >= 8000u) {
            // Cancel only an unassociated, stalled join. Consult the driver too:
            // its CONNECTED event may still be queued on the ESP event task.
            wifi_ap_record_t ap;
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
                __atomic_store_n(&associated, true, __ATOMIC_RELEASE);
            } else {
                wifi_canceling = true;
                if (esp_wifi_disconnect() == ESP_ERR_WIFI_NOT_CONNECT) {
                    __atomic_store_n(&wifi_connecting, false, __ATOMIC_RELEASE);
                    wifi_canceling = false; return false;
                }
                // Await DISCONNECTED before starting another profile, so this
                // attempt's delayed event cannot cancel a later successful join.
            }
        }
        pause_io();
    }
    return false;
}
static int select_wifi(const relay_config_t *settings, deadline_t operation) {
    load_preference(settings);
    unsigned start = first_profile;
    if (network_index >= 0 && (linked() || joining() || wifi_canceling)) start = (unsigned)network_index;
    else if (network_index >= 0 && settings->network_count && __atomic_load_n(&wifi_failed, __ATOMIC_ACQUIRE) &&
             !__atomic_load_n(&wifi_succeeded, __ATOMIC_ACQUIRE))
        start = ((unsigned)network_index + 1) % settings->network_count; // A join failed between background polls.
    for (unsigned attempt = 0; attempt < settings->network_count && live(operation); ++attempt) {
        unsigned index = (start + attempt) % settings->network_count;
        if (connect_wifi(&settings->networks[index], index, operation)) { remember_wifi(index); return (int)index; }
        // DHCP, foreground preemption, USB suspension and a short background
        // deadline do not tear down an association or restart an unfinished join.
        if (linked() || joining() || wifi_canceling || canceled()) return -1;
        first_profile = (index + 1) % settings->network_count;
    }
    return -1;
}
// DNS executes on the TCP/IP task. A reference survives a timed-out caller so a
// late callback can never write to a returned stack or another profile's query.
typedef struct { char host[254]; ip_addr_t address; bool done, valid; int references; } dns_job_t;
static void dns_release(dns_job_t *job) { if (__atomic_sub_fetch(&job->references, 1, __ATOMIC_ACQ_REL) == 0) free(job); }
static void dns_found(const char *name, const ip_addr_t *address, void *arg) {
    (void)name; dns_job_t *job = arg; job->valid = address != NULL; if (address) job->address = *address;
    __atomic_store_n(&job->done, true, __ATOMIC_RELEASE); dns_release(job);
}
static void dns_start(void *arg) {
    dns_job_t *job = arg; ip_addr_t address;
    err_t rc = dns_gethostbyname_addrtype(job->host, &address, dns_found, job,
        __atomic_load_n(&has_ip, __ATOMIC_ACQUIRE) ? LWIP_DNS_ADDRTYPE_IPV4_IPV6 : LWIP_DNS_ADDRTYPE_IPV6_IPV4);
    if (rc == ERR_OK) dns_found(job->host, &address, job);
    else if (rc != ERR_INPROGRESS) dns_found(job->host, NULL, job);
}
static bool resolve(const char *host, ip_addr_t *address, deadline_t deadline) {
    if (ipaddr_aton(host, address)) return true;
    dns_job_t *job = calloc(1, sizeof(*job)); if (!job) return false;
    memcpy(job->host, host, strlen(host) + 1); job->references = 2;
    if (tcpip_callback(dns_start, job) != ERR_OK) { dns_release(job); dns_release(job); return false; }
    while (!__atomic_load_n(&job->done, __ATOMIC_ACQUIRE) && live(deadline)) pause_io();
    bool ok = __atomic_load_n(&job->done, __ATOMIC_ACQUIRE) && job->valid;
    if (ok) *address = job->address;
    dns_release(job); return ok;
}
static int connect_tcp(const char *host, uint16_t port, deadline_t deadline) {
    ip_addr_t address; if (!resolve(host, &address, deadline) || !live(deadline)) return -1;
    struct sockaddr_storage storage = {0}; socklen_t size;
    if (IP_IS_V6(&address)) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage; v6->sin6_family = AF_INET6; v6->sin6_port = htons(port);
        memcpy(&v6->sin6_addr, ip_2_ip6(&address)->addr, 16); size = sizeof(*v6);
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&storage; v4->sin_family = AF_INET; v4->sin_port = htons(port);
        v4->sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(&address)); size = sizeof(*v4);
    }
    int fd = socket(storage.ss_family, SOCK_STREAM, IPPROTO_TCP); if (fd < 0) return -1;
    int no_delay = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay))) { close(fd); return -1; }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) { close(fd); return -1; }
    int rc = connect(fd, (struct sockaddr *)&storage, size);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    while (rc < 0 && live(deadline)) {
        fd_set write_set; FD_ZERO(&write_set); FD_SET(fd, &write_set); struct timeval timeout = {.tv_usec = 5000};
        rc = select(fd + 1, NULL, &write_set, NULL, &timeout);
        if (rc < 0) break;
        if (!rc) { rc = -1; continue; }
        int error = 0; socklen_t length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) { rc = -1; break; }
        rc = 0;
    }
    if (rc < 0 || !live(deadline)) { close(fd); return -1; } return fd;
}
// DER ECDSA-Sig-Value to raw r||s (P-256).
static bool raw_signature(const unsigned char *der, size_t length, uint8_t out[64]) {
    unsigned char *p = (unsigned char *)der, *end = p + length; size_t n;
    mbedtls_mpi r, s; mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    bool ok = !mbedtls_asn1_get_tag(&p, end, &n, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) && p + n == end &&
        !mbedtls_asn1_get_mpi(&p, end, &r) && !mbedtls_asn1_get_mpi(&p, end, &s) && p == end &&
        !mbedtls_mpi_write_binary(&r, out, 32) && !mbedtls_mpi_write_binary(&s, out + 32, 32);
    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); return ok;
}
// The safe end's certificate is issued per service start by its controller key.
// Trust it only if that key is paired on this device; no CA, host name or clock.
static bool trusted_server(const mbedtls_ssl_context *ssl) {
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(ssl);
    uint8_t digest[32], signature[64];
    return peer && !peer->next && peer->MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA256 &&
        peer->MBEDTLS_PRIVATE(sig_pk) == MBEDTLS_PK_ECDSA && !mbedtls_sha256(peer->tbs.p, peer->tbs.len, digest, 0) &&
        raw_signature(peer->MBEDTLS_PRIVATE(sig).p, peer->MBEDTLS_PRIVATE(sig).len, signature) &&
        remote_presence_verify_any(digest, signature);
}
static int tls_random(void *user, unsigned char *out, size_t length) { (void)user; picok_random_fill(out, length); return 0; }
static int tls_send(void *user, const unsigned char *data, size_t length) {
    int n = send(*(int *)user, data, length, 0);
    if (n >= 0) return n;
    return errno == EAGAIN || errno == EWOULDBLOCK ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int tls_receive(void *user, unsigned char *data, size_t length) {
    int n = recv(*(int *)user, data, length, 0);
    if (n >= 0) return n;
    return errno == EAGAIN || errno == EWOULDBLOCK ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static bool tls_io(mbedtls_ssl_context *ssl, uint8_t *buffer, size_t length, bool write_data, deadline_t deadline) {
    while (length && live(deadline)) {
        int n = write_data ? mbedtls_ssl_write(ssl, buffer, length) : mbedtls_ssl_read(ssl, buffer, length);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { pause_io(); continue; }
        if (n <= 0) return false;
        buffer += n; length -= (size_t)n;
    }
    return length == 0;
}
static int network_exchange(const relay_config_t *settings, const uint8_t *request, size_t length,
                            uint8_t *response, size_t capacity, uint16_t *response_length) {
    *response_length = 0; status(1);
    if (!settings || !length || length > RELAY_CTAP_MAX) return 0x03;
    deadline_t operation = {board_millis(), background_active ? 5000u : RELAY_OPERATION_TIMEOUT_MS};
    int result = 0x30;
    int chosen = select_wifi(settings, operation);
    // Once an AP provides an address, only this profile's endpoint is eligible.
    // DNS/TCP/TLS/service failures never rotate Wi-Fi or disconnect the station.
    if (chosen >= 0 && live(operation)) do {
        unsigned index = (unsigned)chosen;
        uint32_t elapsed = (uint32_t)(board_millis() - operation.start);
        if (elapsed >= operation.limit) break;
        uint32_t remaining = operation.limit - elapsed;
        deadline_t profile = {board_millis(), remaining < 8000 ? remaining : 8000};
        if (!boot_id_ready) { picok_random_fill(boot_id, sizeof(boot_id)); boot_id_ready = true; }
        char host[254] = {0}; memcpy(host, settings->networks[index].host, settings->networks[index].host_length);
        phase(4);
        int fd = connect_tcp(host, settings->networks[index].port, profile); if (fd < 0) break;
        mbedtls_ssl_context ssl; mbedtls_ssl_config config;
        mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config);
        do {
            phase(6);
            if (mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) break;
            // Chain verification is replaced by trusted_server() after the handshake;
            // the handshake itself still proves possession of the certificate key.
            mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
            mbedtls_ssl_conf_rng(&config, tls_random, NULL);
            mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
            mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
            static const int suites[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0}; mbedtls_ssl_conf_ciphersuites(&config, suites);
            if (mbedtls_ssl_setup(&ssl, &config)) break;
            mbedtls_ssl_set_bio(&ssl, &fd, tls_send, tls_receive, NULL);
            int rc = MBEDTLS_ERR_SSL_WANT_READ;
            while (live(profile) && (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)) { rc = mbedtls_ssl_handshake(&ssl); if (rc) pause_io(); }
            if (rc || !live(profile) || !trusted_server(&ssl)) break;
            // The safe end's fresh challenge, signed with this device's paired key.
            uint8_t challenge[RELAY_REQUEST_CHALLENGE_SIZE], nonce[32], context[RELAY_REQUEST_CONTEXT_SIZE], digest[32];
            if (!tls_io(&ssl, challenge, sizeof(challenge), false, profile) ||
                !relay_request_challenge_parse(challenge, sizeof(challenge), nonce)) break;
            relay_request_header_t header = {0}; uint8_t wire[RELAY_REQUEST_HEADER_SIZE];
            header.version = 4;
            memcpy(header.serial, pico_serial_str, 16);
            memcpy(header.boot_id, boot_id, sizeof(boot_id));
            picok_random_fill(header.request_id, 16); header.length = (uint16_t)length;
            relay_frame_header_t binding = {0}; memcpy(binding.request_id, header.request_id, 16); mbedtls_sha256(request, length, binding.request_hash, 0);
            bool signed_ok = relay_request_context(&header, nonce, binding.request_hash, context) &&
                !mbedtls_sha256(context, sizeof(context), digest, 0) && remote_presence_device_sign(digest, header.signature);
            if (!signed_ok || !relay_request_encode(&header, wire)) { relay_transport_clear(&header, sizeof(header)); break; }
            // From here, even a partial send makes retry unsafe.
            phase(7);
            bool sent = tls_io(&ssl, wire, sizeof(wire), true, operation) && tls_io(&ssl, (uint8_t *)request, length, true, operation);
            relay_transport_clear(&header, sizeof(header)); relay_transport_clear(wire, sizeof(wire));
            if (!sent) break;
            phase(8);
            while (live(operation)) {
                uint8_t frame_wire[RELAY_FRAME_HEADER_SIZE]; relay_frame_header_t frame;
                if (!tls_io(&ssl, frame_wire, sizeof(frame_wire), false, operation) ||
                    !relay_frame_decode(frame_wire, sizeof(frame_wire), &frame) ||
                    !relay_frame_matches(&frame, binding.request_id, binding.request_hash) || frame.type == RELAY_FRAME_CANCEL) break;
                if (frame.type == RELAY_FRAME_KEEPALIVE) {
                    uint8_t value;
                    if (!tls_io(&ssl, &value, 1, false, operation) || !relay_frame_payload(&frame, &value, 1)) break;
                    status(value); continue;
                }
                if (frame.type == RELAY_FRAME_DISCOVERY) {
                    uint8_t metadata[RELAY_DISCOVERY_SIZE];
                    if (!tls_io(&ssl, metadata, sizeof(metadata), false, operation) ||
                        !relay_frame_payload(&frame, metadata, sizeof(metadata))) break;
                    relay_firmware_discovery(metadata); continue;
                }
                // The response status is separate from the CBOR output buffer.
                uint8_t code;
                if (frame.length - 1u > capacity || !tls_io(&ssl, &code, 1, false, operation) || (code && frame.length != 1)) break;
                if (frame.length > 1 && !tls_io(&ssl, response, frame.length - 1u, false, operation)) break;
                result = code; *response_length = (uint16_t)(frame.length - 1); phase(9); break;
            }
            // Closing this connection is authoritative cancellation. Sending a
            // best-effort CANCEL after USB cancel would require ignoring that
            // cancel in the IO deadline; disconnect already aborts safe-end work.
        } while (0);
        mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config); close(fd);
    } while (0);
    status(1);
    if (canceled()) { if (capacity) mbedtls_platform_zeroize(response, capacity); *response_length = 0; return 0x2d; }
    if (result != 0) { if (capacity) mbedtls_platform_zeroize(response, capacity); *response_length = 0; }
    return result;
}
int relay_network_exchange(const relay_config_t *settings, const uint8_t *request, size_t length,
                           uint8_t *response, size_t capacity, uint16_t *response_length) {
    *response_length = 0;
    if (capacity) mbedtls_platform_zeroize(response, capacity);
    if (!network_mutex) return 0x7f;
    __atomic_store_n(&foreground_waiting, true, __ATOMIC_RELEASE);
    uint32_t start = board_millis();
    while (xSemaphoreTake(network_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
        if (__atomic_load_n(&cancel_button, __ATOMIC_ACQUIRE) || !tud_mounted() || tud_suspended() ||
            (uint32_t)(board_millis() - start) >= RELAY_OPERATION_TIMEOUT_MS) {
            __atomic_store_n(&foreground_waiting, false, __ATOMIC_RELEASE); return 0x2d;
        }
    }
    __atomic_store_n(&foreground_waiting, false, __ATOMIC_RELEASE);
    background_active = false;
    int result = network_exchange(settings, request, length, response, capacity, response_length);
    xSemaphoreGive(network_mutex); return result;
}
void relay_network_refresh(const relay_config_t *settings) {
    if (!network_mutex || __atomic_load_n(&foreground_waiting, __ATOMIC_ACQUIRE) ||
        xSemaphoreTake(network_mutex, 0) != pdTRUE) return;
    background_active = true;
    uint8_t request = 4, response[RELAY_CTAP_MAX]; uint16_t length = 0;
    (void)network_exchange(settings, &request, 1, response, sizeof(response), &length);
    background_active = false; xSemaphoreGive(network_mutex);
}
static void discovery_worker(void *settings) {
    for (;;) {
        if (tud_mounted() && !tud_suspended()) relay_network_refresh((const relay_config_t *)settings);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
void relay_network_start_background(const relay_config_t *settings) {
    // A failed task allocation only loses prefetch: local discovery still works.
    (void)xTaskCreate(discovery_worker, "relay-discovery", 16384, (void *)settings, 1, NULL);
}
#endif
