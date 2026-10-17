#include "relay_control.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> static void rejects(F f) {
    bool failed = false; try { f(); } catch (const std::exception &) { failed = true; }
    check(failed, "operation unexpectedly accepted");
}
struct Harness {
    relay_hid_t firmware{};
    std::unique_ptr<Key> key = Key::generate();
    std::unique_ptr<RelayControl> host;
    uint32_t now = 0;
    unsigned commits = 0, frames = 0;
    bool trusted = true, brokenDigest = false, corruptFrame = false, staleChallenge = false, busy = false;
    Bytes saved;
    static constexpr const char *serial = "0123456789abcdef";
    Harness() {
        relay_setup_callbacks_t cb{}; cb.user = this;
        cb.random = [](void *, uint8_t *nonce) { auto n = randomBytes(32); memcpy(nonce, n.data(), 32); return true; };
        cb.verify = [](void *user, const uint8_t *id, const uint8_t *context, size_t contextLength,
                       const uint8_t *wire, size_t length, const uint8_t *signature, const relay_config_t *) {
            auto &h = *static_cast<Harness *>(user);
            if (!h.trusted || memcmp(id, h.key->id().data(), 16)) return false;
            Bytes bytes(context, context + contextLength); bytes.insert(bytes.end(), wire, wire + length);
            auto digest = hash(bytes);
            secureZero(bytes.data(), bytes.size());
            return crypto::verifyP256(h.key->pub(), digest, Bytes(signature, signature + 64));
        };
        cb.persist = [](void *user, const uint8_t *wire, size_t length) {
            auto &h = *static_cast<Harness *>(user);
            h.saved.assign(wire, wire + length); ++h.commits;
            relay_hid_publish_config(&h.firmware, wire, length);
            auto digest = hash(h.saved); memcpy(h.firmware.stored_digest, digest.data(), 32);
            h.firmware.flags |= RELAY_HID_REBOOT_REQUIRED;
            h.firmware.stored_mode = static_cast<uint8_t>(h.firmware.setup.decoded.mode);
            h.firmware.stored_networks = h.firmware.setup.decoded.network_count;
            return true;
        };
        relay_hid_init(&firmware, reinterpret_cast<const uint8_t *>(serial), cb);
        firmware.flags = RELAY_HID_STORAGE_READY;
        host = std::make_unique<RelayControl>(serial, [this](uint8_t report) {
            Report b{}; check(relay_hid_get(&firmware, report, b.data(), now), "get report");
            if (report == 17 && staleChallenge) b[4] ^= 1;
            if (report == 18 && brokenDigest) b[4] ^= 1;
            return b;
        }, [this](uint8_t report, const Bytes &bytes) {
            check(bytes.size() == 63, "report length"); ++frames;
            auto packet = bytes;
            if (corruptFrame && report == 17) packet[21] ^= 1;
            relay_hid_set(&firmware, report, packet.data(), now, busy);
            secureZero(packet.data(), packet.size());
        });
        host->wait = [this] { now += 10; relay_hid_poll(&firmware, now, busy, false); };
    }
    void physical() {
        relay_hid_poll(&firmware, ++now, false, false);
        relay_hid_poll(&firmware, ++now, false, true);
        now += 1000; relay_hid_poll(&firmware, now, false, true);
        relay_hid_poll(&firmware, ++now, false, false);
    }
};
static relay_config_t fullConfig() {
    relay_config_t c{}; c.mode = RELAY_MODE_RELAY; c.network_count = 10;
    for (auto &n : c.networks) {
        n.ssid_length = 32; memset(n.ssid, 's', 32);
        n.password_length = 64; memset(n.password, 'f', 64);
        const std::string host = std::string(63,'a') + "." + std::string(63,'b') + "." +
                                 std::string(63,'c') + "." + std::string(61,'d');
        n.host_length = 253; memcpy(n.host, host.data(), 253); n.port = 8443;
    }
    return c;
}
int main() {
    try {
        relay_config_t local{};
        {
            Harness h;
            auto c = fullConfig(); auto ticket = h.host->stage(c, *h.key);
            check(!h.host->completed(ticket) && !h.commits && h.frames > 1, "configuration saved before BOOT");
            for (uint8_t report : std::array<uint8_t, 3>{16,17,18}) {
                auto b = h.host->get(report);
                check(std::search(b.begin(), b.end(), c.networks[0].password, c.networks[0].password + 64) == b.end(), "Wi-Fi password leaked in GET report");
            }
            h.physical(); check(h.host->completed(ticket) && h.commits == 1, "end-to-end provisioning");
            auto read = h.host->readConfig();
            check(read.network_count == 10 && read.mode == RELAY_MODE_RELAY &&
                !memcmp(read.networks[9].password, c.networks[9].password, 64), "read-back mismatch");
            relay_config_clear(&read);
            relay_config_t decoded{};
            check(relay_config_decode(h.saved.data(), h.saved.size(), &decoded) == RELAY_CONFIG_OK &&
                decoded.network_count == 10 && decoded.mode == RELAY_MODE_RELAY &&
                !memcmp(decoded.networks[9].password, c.networks[9].password, 64), "saved data changed");
            check(h.host->status().runningMode == RELAY_MODE_LOCAL && h.host->status().storedMode == RELAY_MODE_RELAY,
                "mode switched before reboot");
            h.brokenDigest = true; rejects([&] { h.host->completed(ticket); });
            relay_config_clear(&decoded); relay_config_clear(&c);
        }
        {
            Harness h; auto c = fullConfig();
            memset(c.networks[0].password, 0, sizeof(c.networks[0].password));
            memcpy(c.networks[0].password, RELAY_PASSWORD_TOKEN_PREFIX, RELAY_PASSWORD_TOKEN_PREFIX_LENGTH);
            for (size_t i = RELAY_PASSWORD_TOKEN_PREFIX_LENGTH; i < RELAY_MAX_PASSWORD; ++i)
                c.networks[0].password[i] = "0123456789abcdef"[(i - RELAY_PASSWORD_TOKEN_PREFIX_LENGTH) % 16];
            c.networks[0].password_length = RELAY_MAX_PASSWORD;
            auto ticket = h.host->stage(c, *h.key); h.physical();
            check(h.host->completed(ticket) && h.commits == 1, "sealed-token provisioning");
            auto read = h.host->readConfig();
            check(read.network_count == 10 && read.networks[0].password_length == RELAY_MAX_PASSWORD &&
                !memcmp(read.networks[0].password, c.networks[0].password, RELAY_MAX_PASSWORD),
                "sealed token was not preserved");
            relay_config_clear(&read); relay_config_clear(&c);
        }
        {
            Harness h; auto ticket = h.host->stage(local, *h.key); h.host->cancel(ticket.transaction);
            h.physical(); check(!h.commits && h.host->status().phase == RELAY_SETUP_CANCELED, "cancel committed settings");
        }
        for (unsigned error = 0; error < 4; ++error) {
            Harness h;
            if (error == 0) h.trusted = false;
            if (error == 1) h.corruptFrame = true;
            if (error == 2) h.staleChallenge = true;
            if (error == 3) h.busy = true;
            rejects([&] { h.host->stage(local, *h.key); });
            h.physical(); check(!h.commits, "failed configuration committed");
        }
        {
            Harness h; auto ticket = h.host->stage(local, *h.key);
            auto last = h.host->status(); Bytes replay(63); replay[0] = RELAY_HID_FINISH;
            for (unsigned i = 0; i < 4; ++i) replay[1 + i] = static_cast<unsigned char>(last.sequence >> (8 * i));
            memcpy(replay.data() + 5, ticket.transaction.data(), 16);
            h.host->set(19, replay);
            check(h.host->status().commandResult == RELAY_HID_BAD_SEQUENCE && !h.commits, "duplicate seal accepted");
            h.now += RELAY_SETUP_TIMEOUT_MS; h.host->wait();
            check(h.host->status().phase == RELAY_SETUP_EXPIRED, "setup never expired");
            rejects([&] { h.host->completed(ticket); });
        }
        puts("PASS: host/firmware HID integration, maximum configuration, signature, BOOT, cancellation, stale/corrupt frames and saved digest");
        return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
