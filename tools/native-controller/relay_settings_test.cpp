#include "relay_settings.h"
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> static void rejects(F f) { bool failed = false; try { f(); } catch (...) { failed = true; } check(failed, "accepted invalid data"); }
int main() {
    auto nonce = randomBytes(12);
    auto dir = std::filesystem::temp_directory_path() / ("pf2-settings-test-" + hex(nonce.data(), nonce.size()));
    try {
        const std::string serial = "0123456789abcdef";
        relay_config_t original{}, loaded{};
        loadRelayDraft(serial, loaded, dir);
        check(loaded.mode == RELAY_MODE_LOCAL && loaded.network_count == 0, "new device defaults");
        original.mode = RELAY_MODE_RELAY; original.network_count = 1;
        auto &n = original.networks[0];
        n.ssid_length = 4; memcpy(n.ssid, "test", 4);
        n.password_length = 12; memcpy(n.password, "secret-value", 12);
        n.host_length = 12; memcpy(n.host, "safe.example", 12); n.port = 8443;
        saveRelayDraft(serial, original, dir);
        loadRelayDraft("0123456789ABCDEF", loaded, dir);
        check(loaded.mode == original.mode && loaded.network_count == 1 &&
            !memcmp(loaded.networks[0].password, n.password, 12), "encrypted draft roundtrip");
        auto path = dir / (serial + platform::protectedExtension());
        std::ifstream input(path, std::ios::binary); Bytes encrypted((std::istreambuf_iterator<char>(input)), {}); input.close();
        const Bytes secret{'s','e','c','r','e','t','-','v','a','l','u','e'};
        check(std::search(encrypted.begin(), encrypted.end(), secret.begin(), secret.end()) == encrypted.end(), "plaintext password on disk");
        std::filesystem::copy_file(path, dir / ("fedcba9876543210" + platform::protectedExtension()));
        rejects([&] { loadRelayDraft("fedcba9876543210", loaded, dir); });
        rejects([&] { saveRelayDraft("../../controller", original, dir); });
        // Device trust: physical pairing saves the device public key; forgetting it is revocation.
        const std::string other = "1123456789abcdef";
        auto deviceKey = Key::generate()->pub(), otherKey = Key::generate()->pub();
        check(relayDeviceKey(serial, dir).empty() && relayTrustedDevices(dir).empty(), "untrusted device admitted");
        trustRelayDevice("0123456789ABCDEF", deviceKey, dir); trustRelayDevice(other, otherKey, dir);
        check(relayDeviceKey(serial, dir) == deviceKey && relayDeviceKey(other, dir) == otherKey, "device key roundtrip/alias");
        rejects([&] { trustRelayDevice(serial, Bytes(65, 4), dir); });
        rejects([&] { trustRelayDevice("../bad", deviceKey, dir); });
        check(relayDeviceKey(serial, dir) == deviceKey, "invalid key replaced trusted key");
        auto listed = relayTrustedDevices(dir);
        check(listed == std::vector<std::string>{serial, other}, "trusted device listing");
        auto record = dir / "relay-devices" / (serial + platform::protectedExtension());
        std::filesystem::copy_file(record, dir / "relay-devices" / ("fedcba9876543210" + platform::protectedExtension()));
        rejects([&] { (void)relayDeviceKey("fedcba9876543210", dir); }); // a record moved to another serial
        forgetRelayDevice("fedcba9876543210", dir);
        forgetRelayDevice(serial, dir); forgetRelayDevice(serial, dir); // idempotent, no connected hardware
        check(relayDeviceKey(serial, dir).empty() && relayDeviceKey(other, dir) == otherKey, "revocation scope");
        saveRelayDraft(serial, original, dir);
        check(relayDeviceKey(serial, dir).empty(), "settings draft re-enabled a forgotten device");
        { std::ofstream out(dir / "relay-devices" / (other + platform::protectedExtension()), std::ios::binary | std::ios::trunc); out << "corrupt"; }
        rejects([&] { (void)relayDeviceKey(other, dir); }); // corrupt trust fails closed
        // An unreadable draft can be discarded so the settings window opens empty.
        const std::string stale = "2123456789abcdef";
        { std::filesystem::create_directories(dir); std::ofstream out(dir / (stale + platform::protectedExtension()), std::ios::binary); out << "older format"; }
        rejects([&] { loadRelayDraft(stale, loaded, dir); });
        discardRelayDraft(stale, dir); discardRelayDraft(stale, dir);
        loadRelayDraft(stale, loaded, dir); check(loaded.network_count == 0 && loaded.mode == RELAY_MODE_LOCAL, "discarded draft");
        original.network_count = 11;
        rejects([&] { saveRelayDraft(serial, original, dir); });
        loadRelayDraft(serial, loaded, dir); check(loaded.network_count == 1, "bad draft replaced saved settings");
        encrypted.back() ^= 1;
        { std::ofstream out(path, std::ios::binary | std::ios::trunc); out.write(reinterpret_cast<const char *>(encrypted.data()), encrypted.size()); }
        rejects([&] { loadRelayDraft(serial, loaded, dir); });
        const auto *raw = reinterpret_cast<const uint8_t *>(&loaded);
        check(std::all_of(raw, raw + sizeof(loaded), [](auto b) { return !b; }), "failed load retained secrets");
        relay_config_clear(&original); relay_config_clear(&loaded);
        std::filesystem::remove_all(dir);
        puts("PASS: encrypted settings drafts, per-device identity binding, device key trust/revocation, invalid updates and tamper rejection"); return 0;
    } catch (const std::exception &e) { fprintf(stderr, "FAIL: %s (test directory %s)\n", e.what(), dir.u8string().c_str()); return 1; }
}
