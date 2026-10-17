// Compile the actual ESP adapter, replacing only platform IO. Each scenario and
// every reboot probe runs in a fresh process; production statics are never reset.
#include "relay_tls.h"
#include "relay_control.h"
#include "relay_transport.h"
#include "credentials.h"
#include "cli.h"
#include "test_process.h"
#include "pico_keys.h"
#include "remote_presence.h"
#include "nvs_flash.h"
extern "C" {
#include "relay_firmware.h"
#include "relay_network.h"
#include "relay_password.h"
}
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <optional>
#include <stdexcept>

namespace {
const char plaintext[] = "test-only-wifi-password";
void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class F> void rejects(F f) {
    bool failed = false; try { f(); } catch (const std::exception &) { failed = true; }
    check(failed, "operation unexpectedly accepted");
}
enum class Mode { Local, Relay, Fault };
struct Snapshot { int marker = -1; std::optional<Bytes> blob; Mode mode = Mode::Local; };
Snapshot durable, pending;
std::vector<Snapshot> checkpoints;
std::vector<std::string> operations;
std::unique_ptr<Key> controller;
uint32_t now = 0;
unsigned critical = 0, exchanges = 0, verifications = 0, commits = 0;
unsigned restarts = 0;
bool callback = false, pressed = false, busy = false, pairing = false, trusted = true;
bool cached = false, saving = false;
std::optional<Bytes> networkReply;
Bytes networkRequest;
Bytes savedDiscovery;
bool cacheCommit = false;
int networkResult = 0;
uint8_t networkKeepalive = 2, ledColor = LED_COLOR_OFF;
float ledProgress = 0;
Mode targetMode = Mode::Relay;
std::string failure;
constexpr nvs_handle_t handle = 17;
void io(const char *operation) {
    check(!critical && !callback, "flash/crypto work inside critical section or USB callback");
    operations.emplace_back(operation);
}
void nvsKey(nvs_handle_t h, const char *actual, const char *expected) {
    check(h == handle && strcmp(actual, expected) == 0, "wrong NVS handle or key");
}
Bytes encode(const relay_config_t &config) {
    Bytes wire(RELAY_CONFIG_MAX_SIZE); size_t length = 0;
    check(relay_config_encode(&config, wire.data(), wire.size(), &length) == RELAY_CONFIG_OK, "encode fixture");
    wire.resize(length); return wire;
}
relay_config_t config(unsigned count = 10) {
    relay_config_t c{}; c.mode = RELAY_MODE_RELAY; c.network_count = static_cast<uint8_t>(count);
    for (unsigned i = 0; i < count; ++i) {
        auto &n = c.networks[i]; std::string ssid = "synthetic-" + std::to_string(i);
        n.ssid_length = static_cast<uint8_t>(ssid.size()); memcpy(n.ssid, ssid.data(), ssid.size());
        const std::string password = "test-only-wifi-password", host = "adapter.invalid";
        n.password_length = static_cast<uint8_t>(password.size()); memcpy(n.password, password.data(), password.size());
        n.host_length = static_cast<uint8_t>(host.size()); memcpy(n.host, host.data(), host.size()); n.port = 8443;
    }
    return c;
}
RelayControl host() {
    RelayControl h(pico_serial_str, [](uint8_t report) {
        Report b{}; callback = true; auto n = remote_device_get(report, b.data(), 63); callback = false;
        check(n == 63, "GET report"); return b;
    }, [](uint8_t report, const Bytes &bytes) {
        check(bytes.size() == 63, "SET report length"); callback = true;
        remote_device_set(report, bytes.data(), 63); callback = false;
    });
    h.wait = [] { now += 10; remote_device_service(); };
    return h;
}
void poll(bool down, unsigned elapsed = 1) { pressed = down; now += elapsed; remote_device_service(); }
void physical() { poll(false); poll(true); poll(true, RELAY_SETUP_HOLD_MS); poll(false); }
void checkMode(Mode expected) {
    check(remote_device_local_allowed() == (expected == Mode::Local), "unexpected local credential gate");
    auto c = relay_firmware_config();
    check((c != nullptr) == (expected == Mode::Relay), "unexpected relay credential gate");
    if (expected == Mode::Relay) {
        // Exercise the real LED task with the CBOR path's mounted base mode.
        led_driver = &led_driver_neopixel; led_set_mode(MODE_MOUNTED);
        phy_data.opts = PHY_OPT_LED_STEADY;
        now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_RED && ledProgress == 0, "remote CBOR wait did not start red blink");
        now += 150; led_blinking_task();
        check(ledColor == LED_COLOR_RED && ledProgress > 0 && ledProgress < 1, "remote red wait stuck steady");
        networkKeepalive = 1; now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_OFF, "completed remote wait left LED illuminated");
        led_set_mode(MODE_BUTTON); now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_RED, "relay presence wait did not blink red");
        led_set_mode(MODE_MOUNTED); now += 10; led_blinking_task();
        networkKeepalive = 2; phy_data.opts = 0;
    } else if (expected == Mode::Local) {
        // Only user waits light the LED: processing and idle stay dark.
        led_driver = &led_driver_neopixel; led_set_mode(MODE_PROCESSING);
        now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_OFF, "local processing lit the LED");
        led_set_mode(MODE_BUTTON); now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_GREEN && ledProgress == 0, "local presence wait did not start green blink");
        now += 150; led_blinking_task();
        check(ledColor == LED_COLOR_GREEN && ledProgress > 0 && ledProgress < 1, "local green wait stuck steady");
        led_set_mode(MODE_MOUNTED); now += 10; led_blinking_task();
        check(ledColor == LED_COLOR_OFF, "local idle LED changed");
    }
    auto h = host(); auto s = h.status();
    check(((s.flags & RELAY_HID_BOOT_FAULT) != 0) == (expected == Mode::Fault), "fault status disagrees with credential gate");
    uint8_t response[RELAY_CTAP_MAX]{}, request = 0x04; uint16_t length = 99; unsigned before = exchanges;
    auto rc = remote_device_cbor(0x90, &request, 1, response, sizeof(response), &length);
    if (expected != Mode::Relay) {
        check(rc == 0x7f && length == 0 && exchanges == before, "blocked mode forwarded a request");
        return;
    }
    check(rc == 0 && length > 1 && exchanges == before, "GetInfo depended on network");
    auto info = ctap::decode(Bytes(response, response + length));
    check(info.find(1) && info.find(4)->find("clientPin") && info.find(5)->number == RELAY_CTAP_MAX, "local capabilities invalid");
    for (uint8_t command : {uint8_t(0x0a), uint8_t(0x41)}) {
        length = 99; check(remote_device_cbor(0x90, &command, 1, response, sizeof(response), &length) == 0x2e && !length,
            "credential enumeration allowed");
    }
    check(remote_device_cbor(0x83, &request, 1, response, sizeof(response), &length) == 0x01, "non-CBOR forwarded");
    check(remote_device_cbor(0x90, nullptr, 0, response, sizeof(response), &length) == 0x03, "empty CBOR forwarded");
    check(exchanges == before && remote_device_keepalive() == 2, "invalid request reached network");
    // Actual firmware handles both CTAP 2.0 selection probes using GetInfo only.
    // No PIN cache or registration/assertion reaches the safe end on this path.
    for (uint8_t cmd : {uint8_t(1), uint8_t(2)}) {
        Bytes probe{cmd, 0xa1, static_cast<uint8_t>(cmd == 1 ? 8 : 6), 0x40};
        for (uint8_t pin : {uint8_t(0xf4), uint8_t(0xf5)}) {
            uint8_t metadata[25]{}; metadata[0] = 1; metadata[16] = 1; metadata[24] = pin == 0xf5;
            relay_firmware_discovery(metadata);
            networkResult = 0x30; // Offline cloud/network cannot delay discovery.
            memset(response, 0xa5, sizeof(response));
            check(remote_device_cbor(0x90, probe.data(), probe.size(), response, sizeof(response), &length) == (pin == 0xf5 ? 0x31 : 0x35), "automatic selection PIN state");
            check(exchanges == before && !length && std::all_of(std::begin(response), std::end(response), [](auto b) { return b == 0; }), "probe contacted network or leaked data");
        }
        networkResult = 0; networkReply.reset();
    }
    poll(false); // Persist hints outside the USB callback / critical section.
    // Invalid, duplicate, truncated and nonempty parameters are never mistaken
    // for an automatic selection; ordinary validation still sees the full input.
    for (const auto &requestBytes : std::vector<Bytes>{{1,0xa1,8,0x41,0}, {1,0xa2,8,0x40,8,0x40},
            {1,0xa1,8,0x40,0}, {1,0xa1,8}, {1,0xa1,8,0x60}, {6,0xa1,8,0x40}}) {
        check(remote_device_cbor(0x90, requestBytes.data(), requestBytes.size(), response, sizeof(response), &length) == 0 && networkRequest == requestBytes,
            "ordinary/malformed request treated as automatic selection");
    }
}
void checkBoot(Mode expected) {
    check(!remote_device_local_allowed() && !relay_firmware_config(), "credentials enabled before init");
    remote_device_init(); checkMode(expected);
    auto h = host(); auto s = h.status();
    check(!remote_device_setup_active() && !(s.flags & RELAY_HID_REBOOT_REQUIRED), "stale state after reboot");
    if (expected != Mode::Fault && durable.blob) {
        auto digest = h.get(RELAY_HID_DIGEST);
        check(std::equal(digest.begin() + 4, digest.begin() + 36, hash(*durable.blob).begin()), "stored boot digest");
    }
    if (expected != Mode::Fault) {
        auto read = h.readConfig();
        check(read.mode == s.storedMode && read.network_count == s.storedNetworks, "read-back mode/count");
        for (unsigned i = 0; i < read.network_count; ++i) {
            const auto &n = read.networks[i];
            if (n.password_length)
                check(relay_config_password_token(n.password, n.password_length), "read-back password was not sealed");
            check(std::search(n.password, n.password + n.password_length,
                    plaintext, plaintext + sizeof(plaintext) - 1) == n.password + n.password_length,
                "read-back leaked plaintext password");
        }
        relay_config_clear(&read);
    }
    if (expected == Mode::Relay) {
        relay_config_t stored{};
        check(relay_config_decode(durable.blob->data(), durable.blob->size(), &stored) == RELAY_CONFIG_OK,
              "boot blob decode");
        check(relay_password_resolve_config(&stored, reinterpret_cast<const uint8_t *>(pico_serial_str)),
              "boot token resolution");
        check(encode(*relay_firmware_config()) == encode(stored), "reboot changed configuration");
        relay_config_clear(&stored);
        check(s.runningNetworks == relay_firmware_config()->network_count, "reboot lost network count");
    }
    check(std::none_of(operations.begin(), operations.end(), [](const auto &op) {
        return op == "set-marker" || op == "set-blob" || op == "commit";
    }), "boot changed NVS configuration values");
}
int child(const std::vector<std::string> &arguments) {
    int code = test::run(platform::executablePath(), arguments, 10000);
    check(code >= 0, "child did not exit"); return code;
}
void reboot(const Snapshot &state) {
    auto random = randomBytes(12);
    auto path = std::filesystem::temp_directory_path() / ("pf2-nvs-test-" + hex(random.data(), random.size()) + ".bin");
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.put(static_cast<char>(state.marker)); file.put(state.blob ? 1 : 0);
        if (state.blob) file.write(reinterpret_cast<const char *>(state.blob->data()), state.blob->size());
        check(file.good(), "write synthetic NVS snapshot");
    }
    auto result = child({"--reboot", std::to_string(static_cast<int>(state.mode)), path.u8string()});
    std::filesystem::remove(path); check(result == 0, "reboot did not preserve the expected mode");
}
void setInitial(const relay_config_t &c) {
    durable.marker = 1; durable.blob = encode(c); durable.mode = c.mode == RELAY_MODE_RELAY ? Mode::Relay : Mode::Local;
}
void bootCase(const std::string &name) {
    Mode expected = Mode::Fault;
    relay_config_t local{};
    if (name == "pristine") expected = Mode::Local;
    else if (name == "local") { setInitial(local); expected = Mode::Local; }
    else if (name == "dormant") { auto c = config(); c.mode = RELAY_MODE_LOCAL; setInitial(c); expected = Mode::Local; }
    else if (name == "relay") { setInitial(config()); expected = Mode::Relay; }
    else if (name == "marker-only") durable.marker = 1;
    else if (name == "blob-only") durable.blob = encode(local);
    else if (name == "bad-marker") { setInitial(local); durable.marker = 0; }
    else if (name == "short") { durable.marker = 1; durable.blob = Bytes(RELAY_CONFIG_HEADER_SIZE - 1); }
    else if (name == "long") { durable.marker = 1; durable.blob = Bytes(RELAY_CONFIG_MAX_SIZE + 1); }
    else if (name == "malformed") { setInitial(local); (*durable.blob)[0] ^= 0x80; }
    else { setInitial(config()); failure = name; }
    pending = durable; checkBoot(expected);
}
void runCase(const std::string &name) {
    controller = Key::generate();
    if (name.rfind("restart-", 0) == 0) {
        setInitial(config(1)); pending = durable; checkBoot(Mode::Relay);
        auto original = durable.blob; auto h = host(); check(h.status().canRestart, "restart not advertised");
        if (name == "restart-untrusted") trusted = false;
        if (name == "restart-busy") busy = true;
        if (name == "restart-pairing") pairing = true;
        if (name == "restart-setup") (void)h.stage(config(2), *controller);
        if (name == "restart-ok" || name == "restart-late-busy" || name == "restart-overflow") {
            h.reboot(*controller); check(!restarts, "restarted before acknowledgement delay");
            if (name == "restart-late-busy") busy = true;
            if (name == "restart-overflow") {
                Bytes b(63); for (int i = 0; i < 9; ++i) remote_device_set(22, b.data(), 63);
            }
            poll(false, 600); check(restarts == (name == "restart-ok" ? 1u : 0u), "restart pending cancellation ignored");
            poll(false, 600); check(restarts <= 1, "restart repeated");
        } else { rejects([&] { h.reboot(*controller); }); poll(false, 12000); check(!restarts, "unauthorized/busy restart"); }
        check(durable.blob == original, "restart modified persisted configuration"); return;
    }
    if (name.rfind("cache-", 0) == 0) {
        setInitial(config(1)); pending = durable;
        savedDiscovery.assign(65, 0); memcpy(savedDiscovery.data(), "PF2INF01", 8);
        auto digest = hash(*durable.blob); std::copy(digest.begin(), digest.end(), savedDiscovery.begin() + 8);
        savedDiscovery[40] = 1; savedDiscovery[56] = 1; savedDiscovery[57] = 1;
        if (name == "cache-config-changed") savedDiscovery[8] ^= 1;
        if (name == "cache-corrupt") savedDiscovery[0] ^= 1;
        if (name == "cache-short") savedDiscovery.resize(64);
        remote_device_init();
        uint8_t request = 4, response[RELAY_CTAP_MAX]; uint16_t length;
        auto start = std::chrono::steady_clock::now(); networkResult = 0x30;
        for (unsigned i = 0; i < 1000; ++i) {
            check(remote_device_cbor(0x90, &request, 1, response, sizeof(response), &length) == 0, "cached discovery failed offline");
            auto info = ctap::decode(Bytes(response, response + length));
            check(bool(info.at(4).at("clientPin").number) == (name == "cache-valid"), "cache scope/corruption ignored");
        }
        check(exchanges == 0 && std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "local discovery waited on the cloud");
        // A successfully authenticated different vault replaces the old hint.
        uint8_t metadata[25]{}; metadata[0] = 2; metadata[16] = 1;
        relay_firmware_discovery(metadata); poll(false);
        check(savedDiscovery.size() == 65 && savedDiscovery[40] == 2 && !savedDiscovery[56], "vault switch kept previous PIN hint");
        metadata[16] = 2; metadata[24] = 1; relay_firmware_discovery(metadata);
        metadata[16] = 1; metadata[24] = 0; relay_firmware_discovery(metadata); poll(false);
        check(savedDiscovery[56] == 1 && savedDiscovery[57] == 2, "older server cache replaced a newer PIN hint");
        return;
    }
    if (name.rfind("boot-", 0) == 0) { bootCase(name.substr(5)); return; }
    if (name == "read-write") {
        setInitial(config(2)); pending = durable; checkBoot(Mode::Relay);
        auto h = host();
        auto read = h.readConfig();
        check(read.mode == RELAY_MODE_RELAY && read.network_count == 2, "read-back count");
        check(relay_config_password_token(read.networks[0].password, read.networks[0].password_length),
              "read-back password not sealed");
        const std::string host = "changed.example";
        memset(read.networks[0].host, 0, sizeof(read.networks[0].host));
        memcpy(read.networks[0].host, host.data(), host.size());
        read.networks[0].host_length = static_cast<uint8_t>(host.size());
        auto ticket = h.stage(read, *controller);
        saving = true; targetMode = Mode::Relay; operations.clear();
        physical();
        check(h.completed(ticket), "sealed read-modify-write did not persist");
        check(durable.blob && std::search(durable.blob->begin(), durable.blob->end(),
              plaintext, plaintext + sizeof(plaintext) - 1) == durable.blob->end(),
            "sealed write persisted plaintext");
        relay_config_clear(&read);
        reboot(durable);
        return;
    }
    relay_config_t local{}, next = config(); Mode original = Mode::Local;
    if (name.rfind("relay-", 0) == 0) { setInitial(config(1)); original = Mode::Relay; }
    if (name == "repair") { durable.marker = 1; durable.mode = Mode::Fault; original = Mode::Fault; next = local; }
    if (name == "relay-local") next = local;
    pending = durable; checkBoot(original); auto h = host();
    if (name == "untrusted") trusted = false;
    if (name == "busy") busy = true;
    if (name == "pairing") pairing = true;
    if (name == "untrusted" || name == "busy" || name == "pairing") {
        rejects([&] { h.stage(next, *controller); }); physical(); check(checkpoints.empty(), "unauthorized setup persisted"); return;
    }
    auto ticket = h.stage(next, *controller);
    check(remote_device_setup_active() && !h.completed(ticket) && checkpoints.empty(), "setup saved without physical confirmation");
    // USB reports must never expose the Wi-Fi password.
    for (uint8_t report : {uint8_t(16), uint8_t(17), uint8_t(18)}) {
        auto b = h.get(report);
        if (next.network_count) {
            const auto &n = next.networks[0];
            check(std::search(b.begin(), b.end(), n.password, n.password + n.password_length) == b.end(), "GET leaked password");
        }
    }
    if (name == "cancel") { h.cancel(ticket.transaction); physical(); check(checkpoints.empty(), "canceled save"); return; }
    if (name == "revoke") {
        trusted = false; physical(); check(checkpoints.empty() && h.status().result == RELAY_SETUP_UNAUTHORIZED, "revoked signer persisted"); return;
    }
    if (name == "overflow") {
        Report invalid{}; for (unsigned i = 0; i < 9; ++i) remote_device_set(16, invalid.data(), 63);
        physical(); auto s = h.status();
        check(checkpoints.empty() && s.phase == RELAY_SETUP_CANCELED && s.commandResult == RELAY_HID_BAD_SEQUENCE && !remote_device_setup_active(), "queue overflow did not cancel");
        // The next complete transaction can start normally after the queue is drained.
        ticket = h.stage(next, *controller);
    }
    if (name == "timeout") {
        poll(false, RELAY_SETUP_TIMEOUT_MS); physical(); check(checkpoints.empty() && h.status().phase == RELAY_SETUP_EXPIRED, "expired setup persisted"); return;
    }
    if (name == "fault-retry") {
        saving = true; failure = "read"; physical(); checkMode(Mode::Fault);
        failure.clear(); commits = 0; pending = durable; next = local;
        ticket = h.stage(next, *controller); original = Mode::Fault;
    }
    auto split = name.find("fail-");
    if (split != std::string::npos) failure = name.substr(split + 5);
    cached = name.find("cached-") != std::string::npos; saving = true;
    targetMode = next.mode == RELAY_MODE_RELAY ? Mode::Relay : Mode::Local;
    auto priorBlob = original == Mode::Relay ? encode(*relay_firmware_config()) : Bytes{};
    operations.clear(); physical();
    check(!remote_device_setup_active(), "setup remained active after save");
    if (failure.empty()) {
        check(h.completed(ticket) && commits == 2 && durable.blob == encode(next), "signed physical setup did not persist");
        checkMode(original);
        auto s = h.status(); check((s.flags & RELAY_HID_REBOOT_REQUIRED) && s.storedMode == next.mode, "missing reboot requirement");
        if (original == Mode::Relay) check(encode(*relay_firmware_config()) == priorBlob, "live configuration changed before reboot");
        std::vector<std::string> expected{"verify", "set-marker", "commit", "set-blob", "commit", "get-data"};
        expected.insert(expected.end(), next.network_count, "random");
        check(operations == expected, "persistence order changed");
    } else {
        check(h.status().phase == RELAY_SETUP_ERROR && h.status().result == RELAY_SETUP_STORAGE, "IO failure claimed success");
        checkMode(Mode::Fault); rejects([&] { h.completed(ticket); });
    }
    // Power loss at any completed setter/commit, and reboot after an ambiguous
    // failure, must observe the durable snapshot, never the process's RAM mode.
    for (const auto &point : checkpoints) reboot(point);
    reboot(durable);
}
}

extern "C" {
const char pico_serial_str[17] = "0123456789abcdef";
uint32_t board_millis(void) { return now; }
void test_enter_critical(portMUX_TYPE *) { ++critical; }
void test_exit_critical(portMUX_TYPE *) { check(critical == 1, "critical-section imbalance"); --critical; }
bool is_busy(void) { return busy; }
void esp_restart(void) { io("restart"); check(!busy && !pairing, "restart while busy"); ++restarts; }
bool remote_presence_pairing(void) { return pairing; }
int gpio_get_level(int pin) { check(pin == 0, "wrong BOOT pin"); return pressed ? 0 : 1; }
void picok_random_fill(void *buffer, size_t length) { io("random"); auto b = randomBytes(length); memcpy(buffer, b.data(), length); }
bool remote_presence_derive_key(const char *purpose, uint8_t key[32]) {
    check(purpose && !strcmp(purpose, "pico-fido2 relay password key v1"), "password key purpose");
    memset(key, 0x5a, 32);
    return true;
}
bool remote_presence_verify_digest(const uint8_t id[16], const uint8_t digest[32], const uint8_t signature[64]) {
    io("verify"); ++verifications;
    return trusted && controller && !memcmp(id, controller->id().data(), 16) &&
        crypto::verifyP256(controller->pub(), Bytes(digest, digest + 32), Bytes(signature, signature + 64));
}
esp_err_t nvs_flash_init(void) { io("init"); return failure == "init" ? ESP_FAIL : ESP_OK; }
esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *out) {
    io("open"); check(strcmp(name, "fido_relay") == 0 && mode == NVS_READWRITE, "adapter touched another namespace");
    if (failure == "open") return ESP_FAIL; *out = handle; return ESP_OK;
}
esp_err_t nvs_get_u8(nvs_handle_t h, const char *key, uint8_t *value) {
    io("get-marker"); nvsKey(h, key, "initialized");
    if (failure == "marker-read") return ESP_FAIL;
    if (durable.marker < 0) return ESP_ERR_NVS_NOT_FOUND;
    *value = static_cast<uint8_t>(durable.marker); return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *value, size_t *length) {
    if (!strcmp(key, "info_v1")) {
        check(h == handle && !critical && !callback, "cache read in callback");
        if (savedDiscovery.empty()) return ESP_ERR_NVS_NOT_FOUND;
        if (*length < savedDiscovery.size()) return ESP_ERR_NVS_INVALID_LENGTH;
        if (value) memcpy(value, savedDiscovery.data(), savedDiscovery.size()); *length = savedDiscovery.size(); return ESP_OK;
    }
    io(value ? "get-data" : "get-size"); nvsKey(h, key, "config_v1");
    if ((!value && failure == "size-read") || (value && (failure == "data-read" || failure == "read"))) return ESP_FAIL;
    if (!durable.blob) return ESP_ERR_NVS_NOT_FOUND;
    auto size = durable.blob->size();
    if (value && *length < size) { *length = size; return ESP_ERR_NVS_INVALID_LENGTH; }
    if (value) memcpy(value, durable.blob->data(), size);
    *length = size;
    if (value && (failure == "short-read" || failure == "read-short")) --*length;
    if (value && failure == "read-corrupt" && size) static_cast<uint8_t *>(value)[0] ^= 0x80;
    return ESP_OK;
}
esp_err_t nvs_set_u8(nvs_handle_t h, const char *key, uint8_t value) {
    io("set-marker"); nvsKey(h, key, "initialized"); check(value == 1 && saving, "unexpected marker write");
    if (failure == "marker-before") return ESP_FAIL;
    pending.marker = 1; if (!pending.blob) pending.mode = Mode::Fault;
    if (!cached) durable = pending; checkpoints.push_back(durable);
    return failure == "marker-after" ? ESP_FAIL : ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *value, size_t length) {
    if (!strcmp(key, "info_v1")) {
        check(h == handle && !critical && !callback && length == 65, "cache write in callback");
        auto b = static_cast<const uint8_t *>(value); savedDiscovery.assign(b, b + length); cacheCommit = true; return ESP_OK;
    }
    io("set-blob"); nvsKey(h, key, "config_v1");
    check(saving && commits == 1 && durable.marker == 1, "blob written before durable initialization marker");
    if (failure == "blob-before") return ESP_FAIL;
    auto bytes = static_cast<const uint8_t *>(value); pending.blob = Bytes(bytes, bytes + length); pending.mode = targetMode;
    if (!cached) durable = pending; checkpoints.push_back(durable);
    return failure == "blob-after" ? ESP_FAIL : ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h) {
    if (cacheCommit) { cacheCommit = false; return ESP_OK; }
    io("commit"); check(h == handle && saving, "unexpected commit"); ++commits;
    auto boundary = "commit" + std::to_string(commits);
    if (failure == boundary + "-before") return ESP_FAIL;
    durable = pending; checkpoints.push_back(durable);
    return failure == boundary + "-after" ? ESP_FAIL : ESP_OK;
}
int relay_network_exchange(const relay_config_t *c, const uint8_t *request, size_t length,
                            uint8_t *response, size_t capacity, uint16_t *responseLength) {
    check(c && c->mode == RELAY_MODE_RELAY && c->network_count && length <= capacity, "network received invalid configuration");
    ++exchanges; networkRequest.assign(request, request + length);
    if (networkResult) { *responseLength = 0; return networkResult; }
    const auto &answer = networkReply ? *networkReply : networkRequest;
    check(answer.size() <= capacity, "mock response exceeds buffer");
    memcpy(response, answer.data(), answer.size()); *responseLength = static_cast<uint16_t>(answer.size()); return 0;
}
uint8_t relay_network_keepalive(void) { return networkKeepalive; }
void relay_network_init(void) {}
void relay_network_start_background(const relay_config_t *) {}
void relay_network_diagnostics(uint8_t out[4]) { memset(out, 0, 4); }
test_phy_data_t phy_data{};
static void ledInit() {}
static void ledColorOutput(uint8_t color, uint32_t, float progress) { ledColor = color; ledProgress = progress; }
led_driver_t led_driver_neopixel = {ledInit, ledColorOutput};
}

int main(int argc, char **argv) {
    auto args = commandLine(argc, argv);
    try {
        if (args.size() == 3 && args[0] == "--reboot") {
            std::ifstream file(std::filesystem::u8path(args[2]), std::ios::binary); check(file.good(), "read NVS snapshot");
            auto marker = file.get(); durable.marker = marker == 255 ? -1 : marker;
            bool present = file.get() != 0;
            if (present) durable.blob = Bytes(std::istreambuf_iterator<char>(file), {});
            pending = durable; checkBoot(static_cast<Mode>(std::stoi(args[1]))); return 0;
        }
        if (args.size() == 2 && args[0] == "--case") { runCase(args[1]); return 0; }
        check(args.empty(), "invalid test arguments");
        std::vector<std::string> cases;
        for (const auto &name : {"ok", "untrusted", "busy", "pairing", "setup", "late-busy", "overflow"}) cases.push_back(std::string("restart-") + name);
        for (const auto &name : {"cache-valid", "cache-config-changed", "cache-corrupt", "cache-short"}) cases.emplace_back(name);
        for (const auto &name : {"pristine", "local", "dormant", "relay", "marker-only", "blob-only", "bad-marker", "short", "long",
                "malformed", "init", "open", "marker-read", "size-read", "data-read", "short-read"})
            cases.push_back(std::string("boot-") + name);
        for (const auto &name : {"local-relay", "relay-local", "relay-relay", "repair", "fault-retry", "cancel", "revoke", "overflow", "timeout",
                "untrusted", "busy", "pairing", "read-write"}) cases.emplace_back(name);
        // ESP-IDF 5.5.6 setters persist immediately; commit() is currently a
        // handle-validity check. Also test a cached implementation allowed by
        // the public API so correctness does not depend on that implementation.
        for (const auto &initial : {"local-", "relay-"}) for (const auto &model : {"", "cached-"})
            for (const auto &point : {"marker-before", "marker-after", "commit1-before", "commit1-after", "blob-before", "blob-after",
                    "commit2-before", "commit2-after", "read", "read-short", "read-corrupt"})
                cases.push_back(std::string(initial) + model + "fail-" + point);
        for (const auto &name : cases) {
            if (child({"--case", name}) != 0) throw std::runtime_error("failed scenario: " + name);
        }
        printf("Firmware adapter: %zu isolated scenarios and all durable-snapshot reboot probes passed.\n", cases.size());
        return 0;
    } catch (const std::exception &e) { fprintf(stderr, "Firmware adapter test: %s\n", e.what()); return 1; }
}
