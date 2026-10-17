#pragma once
#include "core.h"
#include "../../shared/relay_hid.h"
#include <functional>

struct RelayStatus {
    uint8_t phase = 0, result = 0, runningMode = 0, storedMode = 0;
    uint8_t runningNetworks = 0, storedNetworks = 0, flags = 0, commandResult = 0, signatureParts = 0;
    uint32_t sequence = 0, remaining = 0;
    uint16_t received = 0, expected = 0;
    Id transaction{};
    // Optional "NET1" tail: last relay attempt phase (1 Wi-Fi init .. 9 done),
    // Wi-Fi disconnect reason, flags (1 ready, 2 associated, 4 IPv4, 8 IPv6), profile.
    bool network = false;
    uint8_t networkPhase = 0, wifiReason = 0, networkFlags = 0, networkProfile = 0;
    bool canRestart = false;
    bool active() const { return phase >= RELAY_SETUP_RECEIVING && phase <= RELAY_SETUP_RELEASE_TO_SAVE; }
};
struct RelayTicket { Id transaction{}; Bytes digest; };

// The injectable transport is also used to run the real host protocol against
// the same HID/state-machine implementation compiled into the firmware.
struct RelayControl {
    std::string serial;
    std::function<Report(uint8_t)> get;
    std::function<void(uint8_t, const Bytes &)> set;
    std::function<void()> wait = [] { sleepMs(10); };
    explicit RelayControl(Device &device);
    RelayControl(std::string serial, std::function<Report(uint8_t)> get,
                 std::function<void(uint8_t, const Bytes &)> set);
    RelayStatus status() const;
    RelayTicket stage(const relay_config_t &config, const Key &key);
    bool completed(const RelayTicket &ticket) const;
    void cancel(const Id &transaction);
    // Reads the stored configuration (not the running one) over GET 19. Wi-Fi
    // passwords come back as device-sealed PF2PW1 tokens; this host cannot
    // decrypt them and must write them back unchanged.
    relay_config_t readConfig() const;
    void reboot(const Key &key);
#ifdef ENABLE_RELAY_DIAGNOSTICS
    std::string diagnostics() const;
#endif
private:
    RelayStatus send(uint8_t report, const Bytes &packet, const Id &transaction, uint32_t sequence);
};
