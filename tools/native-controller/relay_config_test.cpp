#include "../../shared/relay_config.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
using Wire = std::vector<uint8_t>;
static Wire encode(const relay_config_t &config) {
    Wire wire(RELAY_CONFIG_MAX_SIZE);
    size_t n = 0;
    check(relay_config_encode(&config, wire.data(), wire.size(), &n) == RELAY_CONFIG_OK, "encode");
    wire.resize(n);
    return wire;
}
static relay_config_t profile() {
    relay_config_t c{};
    c.mode = RELAY_MODE_RELAY;
    c.network_count = 1;
    auto &n = c.networks[0];
    n.ssid_length = 3; memcpy(n.ssid, "net", 3);
    n.password_length = 8; memcpy(n.password, "password", 8);
    n.host_length = 11; memcpy(n.host, "key.example", 11);
    n.port = 443;
    return c;
}
static void rejectWire(const Wire &wire) {
    relay_config_t output;
    memset(&output, 0xa5, sizeof(output));
    check(relay_config_decode(wire.data(), wire.size(), &output) != RELAY_CONFIG_OK, "invalid wire accepted");
    const auto *bytes = reinterpret_cast<const uint8_t *>(&output);
    check(std::all_of(bytes, bytes + sizeof(output), [](auto b) { return b == 0; }), "secrets remain after rejected decode");
}
static void hostCase(const char *host, bool expected) {
    auto c = profile(); auto &n = c.networks[0];
    auto length = strlen(host);
    check(length <= RELAY_MAX_HOST, "bad host test");
    memset(n.host, 0, sizeof(n.host)); memcpy(n.host, host, length); n.host_length = static_cast<uint8_t>(length);
    check((relay_config_validate(&c) == RELAY_CONFIG_OK) == expected, host);
}
int main() {
    try {
        relay_config_t local{}, decoded{};
        auto wire = encode(local);
        Wire empty{'P','F','2','R','C','F','0','3',0,0};
        check(wire == empty, "default local wire vector");
        auto c = profile(); wire = encode(c);
        Wire expected{'P','F','2','R','C','F','0','3',1,1};
        const Wire tail{3,8,11,0,0xbb,1,'n','e','t','p','a','s','s','w','o','r','d',
                        'k','e','y','.','e','x','a','m','p','l','e'};
        expected.insert(expected.end(), tail.begin(), tail.end());
        check(wire == expected, "network wire vector / LE port");
        check(relay_config_decode(wire.data(), wire.size(), &decoded) == RELAY_CONFIG_OK, "decode vector");
        check(decoded.mode == RELAY_MODE_RELAY && decoded.networks[0].port == 443, "decoded configuration");
        for (size_t n = 0; n < wire.size(); ++n) rejectWire(Wire(wire.begin(), wire.begin() + n));
        auto invalid = wire; invalid.push_back(0); rejectWire(invalid);
        for (auto [index, value] : std::vector<std::pair<size_t,unsigned>>{{7,'2'},{8,2},{9,11},
                {10,33},{11,65},{12,254},{13,1},{14,0},{15,0}}) {
            invalid = wire; invalid[index] = static_cast<uint8_t>(value);
            // Port zero requires clearing both bytes; the two single-byte port mutations remain valid.
            if (index == 14 || index == 15) { invalid[14] = invalid[15] = 0; }
            rejectWire(invalid);
        }
        for (const auto &h : {"localhost", "key.example", "10.0.0.2", "::1", "2001:db8::42", "::", "::ffff:192.0.2.1",
                              "1:2:3:4:5:6:7:8"}) hostCase(h, true);
        for (const auto &h : {"", "https://key.example", "user@host", "host/path", "host\r\nInjected", "host:443", "[::1]",
                              "-bad.example", "bad-.example", "bad..example", "bad.", "::::", "1::2::3", "1:2:3:4:5:6:7",
                              "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::ffff:256.0.0.1", "fe80::1%eth0"}) hostCase(h, false);
        c = profile(); c.network_count = 0;
        check(relay_config_validate(&c) != RELAY_CONFIG_OK, "relay with no profiles");
        c = profile(); c.networks[0].password_length = 0;
        check(relay_config_validate(&c) == RELAY_CONFIG_OK, "open network");
        c.networks[0].password_length = 7;
        check(relay_config_validate(&c) == RELAY_CONFIG_PASSWORD, "short password");
        c.networks[0].password_length = 64; memset(c.networks[0].password, 'f', 64);
        check(relay_config_validate(&c) == RELAY_CONFIG_OK, "raw WPA PSK");
        c.networks[0].password[63] = 'z';
        check(relay_config_validate(&c) == RELAY_CONFIG_PASSWORD, "non-hex WPA PSK");
        c = profile(); c.mode = RELAY_MODE_LOCAL;
        check(relay_config_validate(&c) == RELAY_CONFIG_OK, "retain dormant networks");
        c.mode = RELAY_MODE_RELAY; c.network_count = 10;
        auto &network = c.networks[0];
        network.ssid_length = 32; memset(network.ssid, 's', 32);
        memset(network.password, 0, sizeof(network.password));
        memcpy(network.password, RELAY_PASSWORD_TOKEN_PREFIX, RELAY_PASSWORD_TOKEN_PREFIX_LENGTH);
        for (size_t i = RELAY_PASSWORD_TOKEN_PREFIX_LENGTH; i < RELAY_MAX_PASSWORD; ++i)
            network.password[i] = "0123456789abcdef"[(i - RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) % 16];
        network.password_length = RELAY_MAX_PASSWORD;
        const std::string maximumHost = std::string(63,'a') + "." + std::string(63,'b') + "." +
                                        std::string(63,'c') + "." + std::string(61,'d');
        network.host_length = 253; memcpy(network.host, maximumHost.data(), 253);
        for (unsigned i = 1; i < 10; ++i) c.networks[i] = network;
        auto maximum = encode(c);
        check(maximum.size() == RELAY_CONFIG_MAX_SIZE, "maximum encoded length");
        check(relay_config_decode(maximum.data(), maximum.size(), &decoded) == RELAY_CONFIG_OK, "ten full profiles");
        check(encode(decoded) == maximum, "sealed configuration roundtrip");
        size_t n = 123;
        std::array<uint8_t, 16> small{}; small.fill(0xa5);
        check(relay_config_encode(&c, small.data(), small.size(), &n) == RELAY_CONFIG_CAPACITY && n == 0 &&
              std::all_of(small.begin(), small.end(), [](auto b) { return b == 0xa5; }), "short output modified");
        // Exercise every single-byte mutation and require canonical round trips for
        // accepted inputs. Rejected inputs must leave no partially decoded secrets.
        for (size_t offset = 0; offset < wire.size(); ++offset) {
            for (unsigned v = 0; v < 256; ++v) {
                invalid = wire; invalid[offset] = static_cast<uint8_t>(v);
                if (relay_config_decode(invalid.data(), invalid.size(), &decoded) == RELAY_CONFIG_OK)
                    check(encode(decoded) == invalid, "noncanonical accepted encoding");
                else rejectWire(invalid);
            }
        }
        relay_config_clear(&c); relay_config_clear(&decoded);
        puts("PASS: independent config vectors, ten profiles, bounds, hosts, truncation and mutation coverage");
        return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
