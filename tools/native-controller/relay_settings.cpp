#include "relay_settings.h"
#include "device_names.h"
#include <cstring>
#include <fstream>
#include <algorithm>
#include <stdexcept>

namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Secret {
    Bytes bytes;
    ~Secret() { if (!bytes.empty()) secureZero(bytes.data(), bytes.size()); }
};
std::filesystem::path draftPath(const std::string &serial, const std::filesystem::path &directory) {
    require(validDeviceSerial(serial), "设备序列号不正确");
    std::string canonical = serial;
    for (auto &c : canonical) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    auto base = directory.empty() ? platform::dataDirectory() / "relay-settings" : directory;
    return base / (canonical + platform::protectedExtension());
}
Bytes readBytes(const std::filesystem::path &path, size_t maximum) {
    auto n = std::filesystem::file_size(path);
    require(n > 0 && n <= maximum, "文件长度不正确");
    Bytes out(static_cast<size_t>(n));
    std::ifstream stream(path, std::ios::binary);
    require(bool(stream.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(out.size()))), "读取文件失败");
    return out;
}
constexpr const char *settingsPurpose = "Pico FIDO relay settings v1";
Bytes protect(const Bytes &bytes, bool encrypt) {
    return encrypt ? platform::protect(bytes, settingsPurpose) : platform::unprotect(bytes, settingsPurpose);
}
void atomicWrite(const std::filesystem::path &path, const Bytes &bytes) {
    platform::createPrivateDirectories(path.parent_path());
    platform::publishFile(path, bytes, true, "保存本机中转设置失败");
}
}
void loadRelayDraft(const std::string &serial, relay_config_t &config, const std::filesystem::path &directory) {
    relay_config_clear(&config);
    auto path = draftPath(serial, directory);
    if (!std::filesystem::exists(path)) return;
    Secret encoded; encoded.bytes = readBytes(path, RELAY_CONFIG_MAX_SIZE + 2048);
    Secret raw; raw.bytes = protect(encoded.bytes, false);
    auto canonical = path.stem().string();
    require(raw.bytes.size() >= 24 && !memcmp(raw.bytes.data(), "PF2CFG01", 8) &&
        !memcmp(raw.bytes.data() + 8, canonical.data(), 16), "中转设置文件与所选设备不匹配");
    require(relay_config_decode(raw.bytes.data() + 24, raw.bytes.size() - 24, &config) == RELAY_CONFIG_OK,
            "保存的中转设置不完整");
}
void saveRelayDraft(const std::string &serial, const relay_config_t &config, const std::filesystem::path &directory) {
    auto path = draftPath(serial, directory);
    Secret raw; raw.bytes.resize(24 + RELAY_CONFIG_MAX_SIZE);
    memcpy(raw.bytes.data(), "PF2CFG01", 8);
    auto canonical = path.stem().string(); memcpy(raw.bytes.data() + 8, canonical.data(), 16);
    size_t n = 0;
    require(relay_config_encode(&config, raw.bytes.data() + 24, RELAY_CONFIG_MAX_SIZE, &n) == RELAY_CONFIG_OK,
            "中转设置不完整，未保存");
    raw.bytes.resize(24 + n);
    auto encrypted = protect(raw.bytes, true);
    atomicWrite(path, encrypted);
}
void discardRelayDraft(const std::string &serial, const std::filesystem::path &directory) {
    auto path = draftPath(serial, directory);
    std::error_code error; std::filesystem::remove(path, error);
    require(!error && !std::filesystem::exists(path), "无法删除本机的中转设置草稿");
}
namespace {
constexpr const char *devicePurpose = "Pico FIDO relay device key v1";
std::filesystem::path devicePath(const std::string &serial, const std::filesystem::path &directory) {
    require(validDeviceSerial(serial), "设备序列号不正确");
    std::string canonical = serial;
    for (auto &c : canonical) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    auto base = directory.empty() ? platform::dataDirectory() / "relay-devices" : directory / "relay-devices";
    return base / (canonical + platform::protectedExtension());
}
}
void trustRelayDevice(const std::string &serial, const Bytes &publicKey, const std::filesystem::path &directory) {
    require(crypto::validP256(publicKey), "设备公钥不正确");
    auto path = devicePath(serial, directory); auto canonical = path.stem().string();
    Bytes record{'P','F','2','D','E','V','0','1'}; record.insert(record.end(), canonical.begin(), canonical.end());
    record.insert(record.end(), publicKey.begin(), publicKey.end());
    atomicWrite(path, platform::protect(record, devicePurpose));
    require(relayDeviceKey(serial, directory) == publicKey, "设备公钥保存后无法核对");
}
Bytes relayDeviceKey(const std::string &serial, const std::filesystem::path &directory) {
    auto path = devicePath(serial, directory);
    if (!std::filesystem::exists(path)) return {};
    // An unreadable or mismatched record throws: the server's session fails closed.
    auto record = platform::unprotect(readBytes(path, 4096), devicePurpose); auto canonical = path.stem().string();
    require(record.size() == 8 + 16 + 65 && !memcmp(record.data(), "PF2DEV01", 8) && !memcmp(record.data() + 8, canonical.data(), 16),
            "设备公钥记录与所选设备不匹配");
    Bytes key(record.begin() + 24, record.end());
    require(crypto::validP256(key), "设备公钥记录损坏");
    return key;
}
void forgetRelayDevice(const std::string &serial, const std::filesystem::path &directory) {
    auto path = devicePath(serial, directory);
    std::error_code error; std::filesystem::remove(path, error);
    require(!error && !std::filesystem::exists(path), "无法删除设备公钥；请停止服务后重试");
}
std::vector<std::string> relayTrustedDevices(const std::filesystem::path &directory) {
    auto base = devicePath("0000000000000000", directory).parent_path();
    std::vector<std::string> serials;
    if (!std::filesystem::exists(base)) return serials;
    for (const auto &entry : std::filesystem::directory_iterator(base)) {
        auto serial = entry.path().stem().string();
        if (entry.path().extension() == platform::protectedExtension() && validDeviceSerial(serial)) serials.push_back(serial);
    }
    std::sort(serials.begin(), serials.end()); return serials;
}
