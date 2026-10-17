#include "hid.h"
#include <hidapi.h>
#ifdef __APPLE__
#include <hidapi_darwin.h>
#endif
#include <algorithm>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace hid {
namespace {
constexpr unsigned short vendor = 0x1d50, product = 0x619b;
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void initialize() {
    static std::once_flag once; static int result = 0;
    std::call_once(once, [] {
        result = hid_init();
#ifdef __APPLE__
        hid_darwin_set_open_exclusive(0); // share the FIDO interface with browsers, like Windows/Linux
#endif
    });
    require(result == 0, "无法初始化 USB HID");
}
unsigned short usagePage(Collection c) { return c == Collection::Control ? 0xff31 : 0xf1d0; }
// Firmware serials are 16 ASCII hex digits; anything else is ignored.
bool serialOf(const wchar_t *text, std::string &out) {
    if (!text) return false;
    out.clear();
    for (size_t i = 0; text[i]; ++i) {
        wchar_t c = text[i];
        if (i >= 16 || !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) return false;
        out += static_cast<char>(c);
    }
    return out.size() == 16;
}
hid_device *cast(void *p) { return static_cast<hid_device *>(p); }
}
std::vector<Found> enumerate(Collection collection) {
    initialize();
    std::vector<Found> result;
    auto *list = hid_enumerate(vendor, product);
    for (auto *d = list; d; d = d->next) {
        std::string serial;
        if (d->usage_page != usagePage(collection) || d->usage != 1 || !d->path || !serialOf(d->serial_number, serial)) continue;
        result.push_back({serial, d->path});
    }
    hid_free_enumeration(list);
    std::sort(result.begin(), result.end(), [](const Found &a, const Found &b) { return a.serial != b.serial ? a.serial < b.serial : a.path < b.path; });
    return result;
}
Device::Device(Collection collection, const std::string &serial, const char *missing) {
    auto found = enumerate(collection);
    if (!serial.empty())
        found.erase(std::remove_if(found.begin(), found.end(), [&](const Found &f) { return f.serial != serial; }), found.end());
    require(!found.empty(), missing);
    require(found.size() == 1, "请选择唯一的 ESP32 安全密钥");
    handle = hid_open_path(found.front().path.c_str());
    require(handle != nullptr, collection == Collection::Fido && platform::fidoAccessRequiresElevation() && !platform::isElevated()
        ? "Windows 要求管理员权限才能使用原始 FIDO 接口" : "无法打开所选安全密钥");
    wchar_t text[64]{};
    std::string actual;
    if (hid_get_serial_number_string(cast(handle), text, 63) != 0 || !serialOf(text, actual) || actual != found.front().serial) {
        hid_close(cast(handle)); handle = nullptr;
        throw std::runtime_error("设备序列号不正确");
    }
    id = actual;
}
Device::~Device() { if (handle) hid_close(cast(handle)); }
std::array<unsigned char, 63> Device::getFeature(uint8_t report) {
    unsigned char b[64]{}; b[0] = report;
    int n = hid_get_feature_report(cast(handle), b, sizeof(b));
    require(n >= 64, "USB 读取失败，请重新连接设备"); // report ID + 63 bytes
    require(b[0] == report, "USB 报告不匹配");
    std::array<unsigned char, 63> out{};
    std::memcpy(out.data(), b + 1, std::min<size_t>(63, static_cast<size_t>(n - 1)));
    return out;
}
void Device::setFeature(uint8_t report, const unsigned char *data, size_t length) {
    require(length <= 63, "报告过长");
    unsigned char b[64]{}; b[0] = report;
    if (length) std::memcpy(b + 1, data, length);
    require(hid_send_feature_report(cast(handle), b, sizeof(b)) >= 0, "USB 写入失败，请重新连接设备");
}
void Device::write(const std::array<unsigned char, 64> &packet) {
    unsigned char b[65]{}; std::memcpy(b + 1, packet.data(), 64);
    require(hid_write(cast(handle), b, sizeof(b)) >= 0, "USB 通信中断，请重新连接安全密钥");
}
bool Device::read(std::array<unsigned char, 64> &packet, int timeoutMs) {
    int n = hid_read_timeout(cast(handle), packet.data(), packet.size(), timeoutMs);
    require(n >= 0, "USB 通信中断，请重新连接安全密钥");
    if (n == 0) return false;
    require(n == 64, "USB 通信中断，请重新连接安全密钥");
    return true;
}
}
