#pragma once
#include "relay_control.h"

void loadRelayDraft(const std::string &serial, relay_config_t &config,
                    const std::filesystem::path &directory = {});
void saveRelayDraft(const std::string &serial, const relay_config_t &config,
                    const std::filesystem::path &directory = {});
void discardRelayDraft(const std::string &serial, const std::filesystem::path &directory = {});
// Device public keys learned from physical BOOT pairing on this computer. The
// safe end serves only a device whose request is signed by its saved key, so
// forgetting a lost device needs neither the device nor an unlocked vault.
void trustRelayDevice(const std::string &serial, const Bytes &publicKey, const std::filesystem::path &directory = {});
Bytes relayDeviceKey(const std::string &serial, const std::filesystem::path &directory = {}); // empty: not trusted
void forgetRelayDevice(const std::string &serial, const std::filesystem::path &directory = {});
std::vector<std::string> relayTrustedDevices(const std::filesystem::path &directory = {});
