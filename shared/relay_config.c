#include "relay_config.h"
#include <string.h>

static const uint8_t magic[8] = {'P', 'F', '2', 'R', 'C', 'F', '0', '3'};
static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static void write16(uint8_t *p, uint16_t n) {
    p[0] = (uint8_t)n;
    p[1] = (uint8_t)(n >> 8);
}
void relay_config_clear(relay_config_t *config) {
    if (!config) return;
    volatile uint8_t *p = (volatile uint8_t *)config;
    for (size_t i = 0; i < sizeof(*config); ++i) p[i] = 0;
}
static bool hex_digit(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
bool relay_config_password_plain(const char *p, size_t n) {
    if (!n) return true;
    if (!p || n < 8 || n > RELAY_MAX_PASSWORD_PLAIN) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20 || c > 0x7e) return false;
        if (n == 64 && !hex_digit(c)) return false;
    }
    return true;
}
bool relay_config_password_token(const char *p, size_t n) {
    if (!p || n < RELAY_PASSWORD_TOKEN_MIN_LENGTH || n > RELAY_PASSWORD_TOKEN_MAX_LENGTH ||
        memcmp(p, RELAY_PASSWORD_TOKEN_PREFIX, RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) ||
        (n - RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) % 2) return false;
    size_t raw = (n - RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) / 2;
    if (raw < 12 + 16 || raw > 12 + RELAY_MAX_PASSWORD_PLAIN + 16) return false;
    for (size_t i = RELAY_PASSWORD_TOKEN_PREFIX_LENGTH; i < n; ++i)
        if (!hex_digit((unsigned char)p[i])) return false;
    return true;
}
static bool ipv4(const char *p, size_t n) {
    unsigned parts = 0, value = 0, digits = 0;
    for (size_t i = 0; i <= n; ++i) {
        if (i == n || p[i] == '.') {
            if (!digits || value > 255 || ++parts > 4) return false;
            digits = value = 0;
        } else if (p[i] >= '0' && p[i] <= '9') {
            if (++digits > 3) return false;
            value = value * 10 + (unsigned)(p[i] - '0');
        } else return false;
    }
    return parts == 4;
}
static bool ipv6(const char *p, size_t n) {
    unsigned groups = 0;
    bool compressed = false;
    size_t i = 0;
    if (n < 2) return false;
    if (p[0] == ':') {
        if (p[1] != ':') return false;
        compressed = true;
        i = 2;
    }
    while (i < n) {
        size_t start = i;
        while (i < n && p[i] != ':') ++i;
        size_t len = i - start;
        if (!len) return false;
        if (memchr(p + start, '.', len)) {
            if (i != n || !ipv4(p + start, len)) return false;
            groups += 2;
        } else {
            if (len > 4) return false;
            for (size_t j = start; j < i; ++j) if (!hex_digit((unsigned char)p[j])) return false;
            ++groups;
        }
        if (groups > 8) return false;
        if (i < n) {
            ++i;
            if (i < n && p[i] == ':') {
                if (compressed) return false;
                compressed = true;
                ++i;
            } else if (i == n) return false;
        }
    }
    return compressed ? groups < 8 : groups == 8;
}
static bool host_valid(const char *p, size_t n) {
    if (!n || n > RELAY_MAX_HOST) return false;
    if (memchr(p, ':', n)) return ipv6(p, n);
    size_t label = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)p[i];
        if (c == '.') {
            if (!label || p[i - 1] == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || (c == '-' && label))) return false;
            if (++label > 63) return false;
        }
    }
    return label && p[n - 1] != '-';
}
relay_config_error_t relay_config_validate(const relay_config_t *c) {
    if (!c) return RELAY_CONFIG_FORMAT;
    if (c->mode != RELAY_MODE_LOCAL && c->mode != RELAY_MODE_RELAY) return RELAY_CONFIG_MODE;
    if (c->network_count > RELAY_MAX_NETWORKS ||
        (c->mode == RELAY_MODE_RELAY && !c->network_count)) return RELAY_CONFIG_NETWORK_COUNT;
    // Retaining profiles in local mode is supported.
    for (unsigned i = 0; i < c->network_count; ++i) {
        const relay_network_t *p = &c->networks[i];
        if (!p->ssid_length || p->ssid_length > RELAY_MAX_SSID ||
            memchr(p->ssid, 0, p->ssid_length)) return RELAY_CONFIG_SSID;
        if (p->password_length > RELAY_MAX_PASSWORD ||
            (!relay_config_password_plain(p->password, p->password_length) &&
             !relay_config_password_token(p->password, p->password_length))) return RELAY_CONFIG_PASSWORD;
        if (!host_valid(p->host, p->host_length)) return RELAY_CONFIG_HOST;
        if (!p->port) return RELAY_CONFIG_PORT;
    }
    return RELAY_CONFIG_OK;
}
relay_config_error_t relay_config_encode(const relay_config_t *c, uint8_t *out,
                                          size_t capacity, size_t *length) {
    if (length) *length = 0;
    if (!out || !length) return RELAY_CONFIG_FORMAT;
    relay_config_error_t err = relay_config_validate(c);
    if (err != RELAY_CONFIG_OK) return err;
    size_t total = RELAY_CONFIG_HEADER_SIZE;
    for (unsigned i = 0; i < c->network_count; ++i) {
        const relay_network_t *p = &c->networks[i];
        total += 6u + p->ssid_length + p->password_length + p->host_length;
    }
    if (capacity < total) return RELAY_CONFIG_CAPACITY;
    memcpy(out, magic, sizeof(magic));
    out[8] = (uint8_t)c->mode;
    out[9] = c->network_count;
    size_t offset = RELAY_CONFIG_HEADER_SIZE;
    for (unsigned i = 0; i < c->network_count; ++i) {
        const relay_network_t *p = &c->networks[i];
        out[offset] = p->ssid_length;
        out[offset + 1] = p->password_length;
        out[offset + 2] = p->host_length;
        out[offset + 3] = 0;
        write16(out + offset + 4, p->port);
        offset += 6;
        memcpy(out + offset, p->ssid, p->ssid_length); offset += p->ssid_length;
        memcpy(out + offset, p->password, p->password_length); offset += p->password_length;
        memcpy(out + offset, p->host, p->host_length); offset += p->host_length;
    }
    *length = total;
    return RELAY_CONFIG_OK;
}
relay_config_error_t relay_config_decode(const uint8_t *wire, size_t size, relay_config_t *c) {
    if (!c) return RELAY_CONFIG_FORMAT;
    relay_config_clear(c);
    if (!wire || size < RELAY_CONFIG_HEADER_SIZE || size > RELAY_CONFIG_MAX_SIZE ||
        memcmp(wire, magic, sizeof(magic))) return RELAY_CONFIG_FORMAT;
    relay_config_error_t err = RELAY_CONFIG_FORMAT;
    c->mode = (relay_mode_t)wire[8];
    c->network_count = wire[9];
    if (c->network_count > RELAY_MAX_NETWORKS) goto fail;
    size_t offset = RELAY_CONFIG_HEADER_SIZE;
    for (unsigned i = 0; i < c->network_count; ++i) {
        if (size - offset < 6) goto fail;
        relay_network_t *p = &c->networks[i];
        p->ssid_length = wire[offset];
        p->password_length = wire[offset + 1];
        p->host_length = wire[offset + 2];
        p->port = read16(wire + offset + 4);
        if (wire[offset + 3] || p->ssid_length > RELAY_MAX_SSID ||
            p->password_length > RELAY_MAX_PASSWORD || p->host_length > RELAY_MAX_HOST) goto fail;
        offset += 6;
        size_t span = (size_t)p->ssid_length + p->password_length + p->host_length;
        if (span > size - offset) goto fail;
        memcpy(p->ssid, wire + offset, p->ssid_length); offset += p->ssid_length;
        memcpy(p->password, wire + offset, p->password_length); offset += p->password_length;
        memcpy(p->host, wire + offset, p->host_length); offset += p->host_length;
    }
    if (offset != size) goto fail;
    err = relay_config_validate(c);
    if (err == RELAY_CONFIG_OK) return err;
fail:
    relay_config_clear(c);
    return err;
}
