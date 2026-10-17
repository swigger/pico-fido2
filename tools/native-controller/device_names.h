#pragma once
#include "core.h"

// Local display metadata only. Never sent over HID or included in a FIDO message.
bool validDeviceSerial(const std::string &serial);
void validateDeviceName(const std::wstring &name);
std::wstring loadDeviceName(const std::string &serial,
                           const std::filesystem::path &directory = {});
void saveDeviceName(const std::string &serial, const std::wstring &name,
                    const std::filesystem::path &directory = {});
