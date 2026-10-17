// esp_flasher against a simulated ESP32-S3 ROM loader; zlib plays the ROM's inflater.
#include "esp_flasher.h"
#include "core.h"
#include <mbedtls/md5.h>
#include <zlib.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>

static void check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}
template<class F> static void rejects(F f, const char *message) {
    bool rejected = false;
    try { f(); } catch (const std::exception &) { rejected = true; }
    check(rejected, message);
}
static uint32_t get32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | uint32_t(p[3]) << 24; }
static void put32(Bytes &b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i))); }

class Rom : public esp::Link {
public:
    Bytes flash = Bytes(esp::FlashSize, 0x5a); // old contents
    uint32_t chip = 9, flags = 0; uint8_t crypt = 0;
    int syncsIgnored = 2;
    bool resetSeen = false, rts = false;
    ~Rom() override { if (inflating) inflateEnd(&z); }
    void write(const uint8_t *data, size_t size) override {
        for (size_t i = 0; i < size; ++i) {
            uint8_t b = data[i];
            if (b == 0xc0) { if (!packet.empty()) handle(); packet.clear(); escape = false; }
            else if (escape) { packet.push_back(b == 0xdc ? 0xc0 : 0xdb); escape = false; }
            else if (b == 0xdb) escape = true;
            else packet.push_back(b);
        }
    }
    size_t read(uint8_t *data, size_t size, int) override {
        size_t n = std::min(size, out.size() - sent);
        std::memcpy(data, out.data() + sent, n); sent += n;
        return n;
    }
    void lines(bool dtr, bool r) override { if (r && !dtr && !rts) resetSeen = true; rts = r; }
private:
    Bytes packet, out;
    size_t sent = 0;
    bool escape = false, inflating = false;
    z_stream z{};
    size_t written = 0;
    uint32_t expectSeq = 0;

    void reply(uint8_t op, uint32_t value, Bytes data, uint8_t status = 0) {
        data.push_back(status); data.push_back(status ? 0x05 : 0); data.push_back(0); data.push_back(0);
        Bytes p{0x01, op, uint8_t(data.size()), uint8_t(data.size() >> 8)};
        put32(p, value); p.insert(p.end(), data.begin(), data.end());
        out.push_back(0xc0);
        for (auto b : p) {
            if (b == 0xc0) { out.push_back(0xdb); out.push_back(0xdc); }
            else if (b == 0xdb) { out.push_back(0xdb); out.push_back(0xdd); }
            else out.push_back(b);
        }
        out.push_back(0xc0);
    }
    void handle() {
        check(packet.size() >= 8 && packet[0] == 0, "malformed command");
        uint8_t op = packet[1]; size_t size = packet[2] | packet[3] << 8;
        uint32_t sum = get32(&packet[4]);
        check(packet.size() == 8 + size, "command length");
        const uint8_t *d = &packet[8];
        switch (op) {
        case 0x08:
            if (syncsIgnored-- > 0) return;
            for (int i = 0; i < 8; ++i) reply(op, 0, {});
            return;
        case 0x0a: reply(op, get32(d) == 0x40001000 ? chip : 0, {}); return;
        case 0x14: {
            Bytes info; put32(info, flags); info.push_back(crypt); info.resize(12, 0); put32(info, chip); put32(info, 0);
            reply(op, 0, info); return;
        }
        case 0x0d: case 0x0b: reply(op, 0, {}); return;
        case 0x10:
            check(size == 20 && get32(d) == esp::FlashSize && get32(d + 8) == 0x400 && get32(d + 12) == 0, "begin parameters");
            std::fill(flash.begin(), flash.end(), 0xff);
            if (inflating) inflateEnd(&z);
            z = {}; check(inflateInit(&z) == Z_OK, "inflateInit"); inflating = true; written = 0; expectSeq = 0;
            reply(op, 0, {}); return;
        case 0x11: {
            uint32_t length = get32(d), seq = get32(d + 4);
            check(length == size - 16 && seq == expectSeq++, "data block order");
            uint32_t c = 0xef; for (size_t i = 16; i < size; ++i) c ^= d[i];
            if (c != sum) { reply(op, 0, {}, 1); return; }
            z.next_in = const_cast<uint8_t *>(d + 16); z.avail_in = length;
            while (z.avail_in) {
                z.next_out = flash.data() + written; z.avail_out = uInt(flash.size() - written);
                int r = inflate(&z, Z_NO_FLUSH);
                written = flash.size() - z.avail_out;
                check(r == Z_OK || r == Z_STREAM_END, "compressed stream rejected");
                if (r == Z_STREAM_END) break;
            }
            reply(op, 0, {}); return;
        }
        case 0x13: {
            unsigned char digest[16]; mbedtls_md5(flash.data() + get32(d), get32(d + 4), digest);
            Bytes text; char t[3];
            for (auto b : digest) { std::snprintf(t, 3, "%02X", b); text.push_back(uint8_t(t[0])); text.push_back(uint8_t(t[1])); }
            reply(op, 0, text); return;
        }
        default: reply(op, 0, {}, 1);
        }
    }
};

static Bytes image() {
    Bytes b(0x10000 + 300000, 0xff);
    auto noise = randomBytes(0x7000);
    std::copy(noise.begin(), noise.end(), b.begin() + 0x20);
    for (size_t at : {size_t(0), size_t(0x10000)}) { b[at] = 0xe9; b[at + 12] = 9; b[at + 13] = 0; }
    b[0x8000] = 0xaa; b[0x8001] = 0x50;
    for (size_t i = 0x10020; i < b.size(); ++i) b[i] = uint8_t((i * 7) ^ (i >> 9)); // code-like, partly repetitive
    return b;
}

int main() {
    try {
        // Compression round trip, including runs, random data and an empty input.
        for (auto data : {Bytes{}, Bytes(100000, 0xff), randomBytes(70000), image()}) {
            auto packed = esp::deflate(data);
            Bytes back(data.size() + 1); uLongf n = uLongf(back.size());
            check(uncompress(back.data(), &n, packed.data(), uLong(packed.size())) == Z_OK && n == data.size() &&
                std::equal(data.begin(), data.end(), back.begin()), "deflate round trip");
        }
        check(esp::deflate(Bytes(esp::FlashSize, 0xff)).size() < 30000, "erased flash compresses");

        auto firmware = image();
        Rom rom; esp::Progress progress;
        esp::flash(rom, firmware, progress);
        Bytes expected = firmware; expected.resize(esp::FlashSize, 0xff);
        check(rom.flash == expected, "flash contents");
        check(progress.stage == esp::Progress::Done && progress.permille == 1000 && rom.resetSeen, "finish and reset");

        Rom other; other.chip = 5;
        rejects([&] { esp::Progress p; esp::flash(other, firmware, p); }, "non-S3 chip accepted");
        check(other.flash[0] == 0x5a, "non-S3 chip touched");
        Rom secure; secure.flags = 1;
        rejects([&] { esp::Progress p; esp::flash(secure, firmware, p); }, "secure boot chip accepted");
        Rom encrypted; encrypted.crypt = 1;
        rejects([&] { esp::Progress p; esp::flash(encrypted, firmware, p); }, "encrypted chip accepted");
        Rom cancelled; esp::Progress stop; stop.cancel = true;
        rejects([&] { esp::flash(cancelled, firmware, stop); }, "cancel ignored");

        auto bad = firmware; bad[0x8000] = 0;
        rejects([&] { esp::checkImage(bad); }, "missing partition table accepted");
        bad = firmware; bad[12] = 5;
        rejects([&] { esp::checkImage(bad); }, "other chip's image accepted");
        rejects([&] { esp::checkImage(Bytes(esp::FlashSize + 1, 0xff)); }, "oversized image accepted");
        std::puts("PASS: deflate round trip, full-flash write and MD5 verify, chip/security refusal, cancel and image checks");
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
