#include "esp_flasher.h"
#include <mbedtls/md5.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace esp {
namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void put32(Bytes &b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i))); }
uint32_t get32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | static_cast<uint32_t>(p[3]) << 24; }
Bytes words(std::initializer_list<uint32_t> values) { Bytes b; for (auto v : values) put32(b, v); return b; }

// ROM loader commands (esptool "serial protocol").
enum : uint8_t { Sync = 0x08, ReadReg = 0x0a, SpiSetParams = 0x0b, SpiAttach = 0x0d,
                 DeflBegin = 0x10, DeflData = 0x11, FlashMd5 = 0x13, SecurityInfo = 0x14 };
constexpr uint32_t ChipDetectMagic = 0x40001000, Esp32S3 = 9, BlockSize = 0x400;
constexpr uint16_t ImageChipS3 = 9;

class Loader {
public:
    Loader(Link &link, Progress &progress) : link(link), progress(progress) {}
    void sync() {
        Bytes data{0x07, 0x07, 0x12, 0x20}; data.resize(36, 0x55);
        for (int attempt = 0; attempt < 10; ++attempt) {
            cancelled();
            send(Sync, data, 0);
            Reply reply;
            if (!receive(Sync, reply, 200)) continue;
            Bytes extra;
            while (frame(extra, 100)) {} // the ROM answers each SYNC several times
            return;
        }
        throw std::runtime_error("下载模式的芯片没有响应。请拔下设备，按住 BOOT 重新插入 USB 后再试");
    }
    // The first plain reply tells how many status bytes this loader appends.
    uint32_t readReg(uint32_t address) {
        auto reply = command(ReadReg, words({address}), 0, 1000);
        require(reply.data.size() == 2 || reply.data.size() == 4, "芯片应答格式无法识别");
        statusLength = reply.data.size();
        check(reply, ReadReg);
        return reply.value;
    }
    // Returns the payload without status bytes; throws if the ROM reports an error.
    Bytes call(uint8_t op, const Bytes &data, uint32_t checksum, int timeoutMs) {
        auto reply = command(op, data, checksum, timeoutMs);
        check(reply, op);
        reply.data.resize(reply.data.size() - statusLength);
        return reply.data;
    }
    void cancelled() const {
        if (progress.cancel) throw std::runtime_error("已取消刷写。芯片可能已被部分擦除，请重新刷写后再使用");
    }
private:
    struct Reply { uint32_t value = 0; Bytes data; };
    Link &link;
    Progress &progress;
    Bytes pending;
    size_t next = 0;
    size_t statusLength = 4;

    void send(uint8_t op, const Bytes &data, uint32_t checksum) {
        Bytes packet{0x00, op, static_cast<uint8_t>(data.size()), static_cast<uint8_t>(data.size() >> 8)};
        put32(packet, checksum);
        packet.insert(packet.end(), data.begin(), data.end());
        Bytes slip{0xc0};
        for (auto b : packet) {
            if (b == 0xc0) { slip.push_back(0xdb); slip.push_back(0xdc); }
            else if (b == 0xdb) { slip.push_back(0xdb); slip.push_back(0xdd); }
            else slip.push_back(b);
        }
        slip.push_back(0xc0);
        link.write(slip.data(), slip.size());
    }
    // One SLIP frame, or false on timeout.
    bool frame(Bytes &out, int timeoutMs) {
        auto deadline = tickMs() + static_cast<uint64_t>(timeoutMs);
        out.clear();
        bool inside = false, escape = false;
        for (;;) {
            while (next < pending.size()) {
                uint8_t b = pending[next++];
                if (!inside) { inside = b == 0xc0; continue; }
                if (b == 0xc0) { if (out.empty()) continue; return true; }
                if (escape) { out.push_back(b == 0xdc ? 0xc0 : b == 0xdd ? 0xdb : b); escape = false; }
                else if (b == 0xdb) escape = true;
                else out.push_back(b);
            }
            auto now = tickMs();
            if (now >= deadline) return false;
            uint8_t buffer[512];
            auto n = link.read(buffer, sizeof(buffer), static_cast<int>(std::min<uint64_t>(deadline - now, 200)));
            pending.assign(buffer, buffer + n); next = 0;
            if (!n) cancelled();
        }
    }
    bool receive(uint8_t op, Reply &reply, int timeoutMs) {
        auto deadline = tickMs() + static_cast<uint64_t>(timeoutMs);
        Bytes f;
        while (tickMs() < deadline) {
            if (!frame(f, static_cast<int>(deadline - std::min(deadline, tickMs())))) return false;
            if (f.size() < 8 || f[0] != 0x01 || f[1] != op) continue; // stale SYNC replies, boot noise
            size_t size = f[2] | f[3] << 8;
            if (f.size() < 8 + size) continue;
            reply.value = get32(&f[4]);
            reply.data.assign(f.begin() + 8, f.begin() + 8 + static_cast<std::ptrdiff_t>(size));
            return true;
        }
        return false;
    }
    Reply command(uint8_t op, const Bytes &data, uint32_t checksum, int timeoutMs) {
        cancelled();
        send(op, data, checksum);
        Reply reply;
        if (!receive(op, reply, timeoutMs)) throw std::runtime_error("芯片没有响应，刷写中断。请重新进入下载模式后再试");
        return reply;
    }
    void check(const Reply &reply, uint8_t op) const {
        require(reply.data.size() >= statusLength, "芯片应答不完整");
        const auto *status = &reply.data[reply.data.size() - statusLength];
        if (status[0] == 0) return;
        char text[96];
        std::snprintf(text, sizeof(text), "芯片拒绝了命令 0x%02X（错误 0x%02X）", op, status[1]);
        throw std::runtime_error(text);
    }
};

uint32_t checksum(const uint8_t *data, size_t size) {
    uint32_t c = 0xef;
    for (size_t i = 0; i < size; ++i) c ^= data[i];
    return c;
}
std::string md5Hex(const Bytes &data) {
    unsigned char digest[16];
    require(mbedtls_md5(data.data(), data.size(), digest) == 0, "MD5 计算失败");
    char text[33];
    for (int i = 0; i < 16; ++i) std::snprintf(text + 2 * i, 3, "%02x", digest[i]);
    return text;
}
uint16_t imageChip(const Bytes &image, size_t offset) { return static_cast<uint16_t>(image[offset + 12] | image[offset + 13] << 8); }

// --- deflate: one fixed-Huffman block with greedy LZ77 matching ---
struct Bits {
    Bytes &out; uint32_t acc = 0; int count = 0;
    void put(uint32_t value, int n) {
        acc |= value << count; count += n;
        while (count >= 8) { out.push_back(static_cast<uint8_t>(acc)); acc >>= 8; count -= 8; }
    }
    void code(uint32_t value, int n) { // Huffman codes go most significant bit first
        uint32_t r = 0;
        for (int i = 0; i < n; ++i) r |= ((value >> i) & 1) << (n - 1 - i);
        put(r, n);
    }
    void symbol(unsigned s) {
        if (s < 144) code(0x30 + s, 8);
        else if (s < 256) code(0x190 + s - 144, 9);
        else if (s < 280) code(s - 256, 7);
        else code(0xc0 + s - 280, 8);
    }
    void flush() { if (count) out.push_back(static_cast<uint8_t>(acc)); acc = 0; count = 0; }
};
constexpr uint16_t lengthBase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr uint8_t lengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr uint16_t distBase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
                                   2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr uint8_t distExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
}

Bytes deflate(const Bytes &data) {
    constexpr size_t Window = 32768, HashSize = 1 << 16, MaxMatch = 258;
    Bytes out{0x78, 0x01};
    Bits bits{out};
    bits.put(1, 1); bits.put(1, 2); // final block, fixed Huffman
    std::vector<int64_t> head(HashSize, -1), prev(Window, -1);
    auto hash = [&](size_t i) { return ((data[i] << 16 | data[i + 1] << 8 | data[i + 2]) * 2654435761u) >> 16; };
    auto insert = [&](size_t i) {
        if (i + 3 > data.size()) return;
        auto h = hash(i); prev[i % Window] = head[h]; head[h] = static_cast<int64_t>(i);
    };
    size_t n = data.size();
    for (size_t i = 0; i < n;) {
        size_t best = 0, distance = 0;
        if (i + 3 <= n) {
            size_t limit = std::min(MaxMatch, n - i);
            int64_t c = head[hash(i)];
            for (int chain = 0; c >= 0 && i - static_cast<size_t>(c) <= Window && chain < 64; ++chain) {
                size_t at = static_cast<size_t>(c), len = 0;
                while (len < limit && data[at + len] == data[i + len]) ++len;
                if (len > best) { best = len; distance = i - at; if (len == limit) break; }
                auto next = prev[at % Window];
                if (next >= c) break; // slot reused by a newer position
                c = next;
            }
        }
        if (best >= 3) {
            int l = 28; while (lengthBase[l] > best) --l;
            bits.symbol(257 + static_cast<unsigned>(l)); bits.put(static_cast<uint32_t>(best - lengthBase[l]), lengthExtra[l]);
            int d = 29; while (distBase[d] > distance) --d;
            bits.code(static_cast<uint32_t>(d), 5); bits.put(static_cast<uint32_t>(distance - distBase[d]), distExtra[d]);
            for (size_t k = 0; k < best; ++k) insert(i + k);
            i += best;
        } else { bits.symbol(data[i]); insert(i); ++i; }
    }
    bits.symbol(256);
    bits.flush();
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n;) {
        size_t end = std::min(n, i + 5552);
        for (; i < end; ++i) { a += data[i]; b += a; }
        a %= 65521; b %= 65521;
    }
    uint32_t adler = b << 16 | a;
    for (int s = 24; s >= 0; s -= 8) out.push_back(static_cast<uint8_t>(adler >> s));
    return out;
}

void checkImage(const Bytes &image) {
    require(image.size() > 0x10000 + 24 && image.size() <= FlashSize,
        "固件文件大小不对：需要包含 bootloader、分区表和应用的合并镜像（esp32s3supermini-*.bin）");
    require(image[0] == 0xe9 && imageChip(image, 0) == ImageChipS3, "固件文件开头不是 ESP32-S3 bootloader，请选择合并镜像");
    require(image[0x8000] == 0xaa && image[0x8001] == 0x50, "固件文件在 0x8000 处缺少分区表，请选择合并镜像");
    require(image[0x10000] == 0xe9 && imageChip(image, 0x10000) == ImageChipS3, "固件文件在 0x10000 处缺少 ESP32-S3 应用");
}
Bytes readImage(const std::filesystem::path &path) {
    auto image = platform::readFile(path, FlashSize, "无法读取固件文件");
    checkImage(image);
    return image;
}

void flash(Link &link, const Bytes &image, Progress &progress, bool reset) {
    checkImage(image);
    progress.permille = 0;
    progress.stage = Progress::Connecting;
    Loader loader(link, progress);
    loader.sync();
    auto magic = loader.readReg(ChipDetectMagic);
    auto info = loader.call(SecurityInfo, {}, 0, 1000);
    require(info.size() >= 12, "无法读取芯片安全状态");
    uint32_t chip = info.size() >= 20 ? get32(&info[12]) : magic;
    require(chip == Esp32S3, "连接的不是 ESP32-S3 芯片，已停止。目前只支持 ESP32-S3");
    require(!(get32(&info[0]) & 1), "芯片已启用 Secure Boot，不能用本工具刷写");
    int crypt = 0; for (int bit = 0; bit < 8; ++bit) crypt += (info[4] >> bit) & 1;
    require(!(crypt & 1), "芯片已启用 Flash 加密，不能用本工具刷写");
    loader.call(SpiAttach, Bytes(8, 0), 0, 3000);
    loader.call(SpiSetParams, words({0, FlashSize, 64 * 1024, 4 * 1024, 256, 0xffff}), 0, 1000);

    // Padding with 0xFF overwrites every byte, so nothing of the old contents survives.
    Bytes padded = image; padded.resize(FlashSize, 0xff);
    auto compressed = deflate(padded);
    auto blocks = static_cast<uint32_t>((compressed.size() + BlockSize - 1) / BlockSize);
    progress.stage = Progress::Erasing;
    loader.call(DeflBegin, words({FlashSize, blocks, BlockSize, 0, 0}), 0, 150000);
    progress.stage = Progress::Writing;
    for (uint32_t seq = 0; seq < blocks; ++seq) {
        size_t offset = size_t(seq) * BlockSize, size = std::min<size_t>(BlockSize, compressed.size() - offset);
        auto data = words({static_cast<uint32_t>(size), seq, 0, 0});
        data.insert(data.end(), compressed.begin() + static_cast<std::ptrdiff_t>(offset),
                    compressed.begin() + static_cast<std::ptrdiff_t>(offset + size));
        loader.call(DeflData, data, checksum(&compressed[offset], size), 30000);
        progress.permille = static_cast<int>((seq + 1) * 1000ull / blocks);
    }
    progress.stage = Progress::Verifying;
    auto digest = loader.call(FlashMd5, words({0, FlashSize, 0, 0}), 0, 60000);
    std::string actual;
    if (digest.size() == 32) actual.assign(digest.begin(), digest.end());
    else if (digest.size() == 16) { char t[3]; for (auto b : digest) { std::snprintf(t, 3, "%02x", b); actual += t; } }
    std::transform(actual.begin(), actual.end(), actual.begin(), [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
    require(actual == md5Hex(padded), "写入后校验不一致，请重新刷写");
    if (reset) {
        progress.stage = Progress::Resetting;
        // USB serial/JTAG: RTS asserted with DTR released resets the chip.
        try { link.lines(false, false); link.lines(false, true); sleepMs(200); link.lines(false, false); } catch (...) {}
    }
    progress.stage = Progress::Done;
}

}
