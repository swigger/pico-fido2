#include "device_names.h"
#include <algorithm>
#include <fstream>
#include <stdexcept>

bool validDeviceSerial(const std::string &serial) {
    return serial.size() == 16 && std::all_of(serial.begin(), serial.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}
void validateDeviceName(const std::wstring &name) {
    if (utf8(name).size() > 32)
        throw std::runtime_error("设备名称最多 32 个 UTF-8 字节（中文通常每字 3 字节）");
    for (auto c : name) {
        // Names are single-line labels. Reject invisible direction overrides as well.
        if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c == 0x061c ||
            c == 0x200e || c == 0x200f || (c >= 0x2028 && c <= 0x202e) ||
            (c >= 0x2066 && c <= 0x2069))
            throw std::runtime_error("设备名称不能包含控制字符或方向控制符");
    }
}
static std::filesystem::path namePath(const std::string &serial,
                                      const std::filesystem::path &directory) {
    if (!validDeviceSerial(serial)) throw std::runtime_error("设备序列号不正确");
    std::string normalized = serial;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
        return c >= 'A' && c <= 'F' ? static_cast<char>(c + ('a' - 'A')) : static_cast<char>(c);
    });
    auto dir = directory.empty() ? platform::dataDirectory() / "device-names" : directory;
    return dir / (normalized + ".name");
}
std::wstring loadDeviceName(const std::string &serial, const std::filesystem::path &directory) {
    auto path = namePath(serial, directory);
    if (!std::filesystem::exists(path)) return {};
    auto size = std::filesystem::file_size(path);
    if (size > 32) throw std::runtime_error("保存的设备名称过长");
    std::string raw(static_cast<size_t>(size), '\0');
    std::ifstream in(path, std::ios::binary);
    if (!in.read(raw.data(), static_cast<std::streamsize>(raw.size())))
        throw std::runtime_error("读取设备名称失败");
    auto name = widen(raw);
    validateDeviceName(name);
    return name;
}
void saveDeviceName(const std::string &serial, const std::wstring &name,
                    const std::filesystem::path &directory) {
    validateDeviceName(name);
    auto path = namePath(serial, directory);
    auto text = utf8(name);
    platform::createPrivateDirectories(path.parent_path());
    platform::publishFile(path, Bytes(text.begin(), text.end()), true, "保存设备名称失败，旧名称保持不变");
}
