#pragma once
// Writes a merged ESP32-S3 firmware image to a chip in ROM download mode (BOOT
// held while plugging in USB) over its built-in USB serial port. The ROM loader
// protocol is used directly (no esptool, no flasher stub): the whole 4 MB flash
// is erased and rewritten, so everything previously on the chip is lost.
#include "platform.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace esp {

constexpr uint32_t FlashSize = 4u << 20;

// A serial port in download mode: the chip's ROM USB device (303A:1001).
struct DownloadPort { std::string path, label; };
std::vector<DownloadPort> downloadPorts();

// Byte transport to the ROM loader; implemented by the system serial port and
// by the tests' simulated chip.
class Link {
public:
    virtual ~Link() = default;
    virtual void write(const uint8_t *data, size_t size) = 0;
    // Returns 0 on timeout.
    virtual size_t read(uint8_t *data, size_t size, int timeoutMs) = 0;
    virtual void lines(bool dtr, bool rts) = 0;
};
std::unique_ptr<Link> openSerial(const std::string &path);

// Throws a user-facing message unless image is a complete ESP32-S3 flash image
// starting at offset 0 (bootloader, partition table at 0x8000, app at 0x10000).
void checkImage(const Bytes &image);
Bytes readImage(const std::filesystem::path &path);

// zlib stream (fixed Huffman, LZ77) as accepted by the ROM's deflate commands.
Bytes deflate(const Bytes &data);

struct Progress {
    enum Stage { Idle, Connecting, Erasing, Writing, Verifying, Resetting, Done };
    std::atomic<int> stage{Idle}, permille{0};
    std::atomic_bool cancel{false};
};

// Erases the whole flash, writes image at 0 (padded with 0xFF), verifies the
// MD5 of all 4 MB and resets the chip. Refuses chips other than ESP32-S3 and
// chips with Secure Boot or flash encryption enabled. Throws on failure.
void flash(Link &link, const Bytes &image, Progress &progress, bool reset = true);

}
