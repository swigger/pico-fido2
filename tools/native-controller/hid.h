#pragma once
// USB HID access through hidapi. The firmware exposes two collections on the
// same serial: the vendor control collection (usage page 0xff31, 64-byte
// feature reports) and the standard FIDO collection (usage page 0xf1d0).
#include "platform.h"
#include <array>
#include <memory>
#include <string>

namespace hid {
enum class Collection { Control, Fido };
struct Found { std::string serial, path; };
// Sorted by serial; only 16-hex-digit serials of the Pico FIDO VID/PID.
std::vector<Found> enumerate(Collection collection);

class Device {
public:
    // Opens exactly one matching collection with this serial, or throws.
    Device(Collection collection, const std::string &serial, const char *missing);
    ~Device();
    Device(const Device &) = delete;
    Device &operator=(const Device &) = delete;
    const std::string &serial() const { return id; }
    // Feature reports: 63 payload bytes after the report ID.
    std::array<unsigned char, 63> getFeature(uint8_t report);
    void setFeature(uint8_t report, const unsigned char *data, size_t length);
    // Interrupt reports: 64 bytes, report ID 0.
    void write(const std::array<unsigned char, 64> &packet);
    // Returns false on timeout (no data within timeoutMs).
    bool read(std::array<unsigned char, 64> &packet, int timeoutMs);
private:
    void *handle = nullptr;
    std::string id;
};
}
