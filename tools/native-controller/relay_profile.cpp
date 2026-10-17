#include "relay_profile.h"
#include "relay_cloud.h"
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace relay {
namespace {
struct Text { std::string s; ~Text() { if (!s.empty()) secureZero(s.data(), s.size()); } };
void quote(std::string &out, const std::string &s) {
    auto put = [&](char c) { if (out.size() >= 256 * 1024) throw std::runtime_error("云配置超出大小限制"); out += c; };
    put('"');
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { put('\\'); put(static_cast<char>(c)); }
        else if (c < 32) { const char *hex = "0123456789abcdef"; for (char prefix : std::string("\\u00")) put(prefix); put(hex[c >> 4]); put(hex[c & 15]); }
        else put(static_cast<char>(c));
    }
    put('"');
}
std::string read(const std::filesystem::path &path, size_t maximum) {
    auto n = std::filesystem::file_size(path);
    if (!n || n > maximum) throw std::runtime_error("证书或私钥文件大小不正确");
    Text text{std::string(static_cast<size_t>(n), '\0')}; std::ifstream f(path, std::ios::binary);
    if (!f.read(text.s.data(), static_cast<std::streamsize>(n))) throw std::runtime_error("无法读取证书或私钥文件");
    if (!validUtf8(text.s)) throw std::runtime_error("证书或私钥文件不是有效文本");
    return std::move(text.s);
}
void add(std::string &json, const char *prefix, const std::string &value) {
    if (json.size() + strlen(prefix) >= 256 * 1024) throw std::runtime_error("云配置超出大小限制");
    json += prefix; quote(json, value);
}
void common(std::string &json, const CloudProfileFields &p, const std::string &provider) {
    (void)CloudStorage::identity(p.nameSpace);
    Text ca{read(p.ca, 65536)}, cert{read(p.certificate, 65536)}, key{read(p.privateKey, 16384)};
    add(json, "{\"profile\":{\"version\":1,\"namespace\":", p.nameSpace);
    add(json, ",\"coordinator\":{\"endpoints\":[", p.coordinator); add(json, "],\"ca_pem\":", ca.s);
    add(json, ",\"client_cert_pem\":", cert.s); add(json, ",\"client_key_pem\":", key.s);
    add(json, ",\"cluster_id\":\"\"},\"provider\":{\"provider\":", provider); add(json, ",\"root\":", p.root);
}
Bytes finish(std::string &json, const char *suffix) {
    if (json.size() + strlen(suffix) > 256 * 1024) throw std::runtime_error("云配置超出大小限制");
    json += suffix; return Bytes(json.begin(), json.end());
}
}
WebDavProfile::~WebDavProfile() { if (!password.empty()) secureZero(password.data(), password.size() * sizeof(wchar_t)); }
OAuthProfile::~OAuthProfile() { if (!clientSecret.empty()) secureZero(clientSecret.data(), clientSecret.size() * sizeof(wchar_t)); }
ProfileMaintenance::~ProfileMaintenance() {
    if (!secret.empty()) secureZero(secret.data(), secret.size() * sizeof(wchar_t));
    if (!clientSecret.empty()) secureZero(clientSecret.data(), clientSecret.size() * sizeof(wchar_t));
}
Bytes webDavProfileSetup(const WebDavProfile &p) {
    // Reserve once and append quoted secrets directly. Avoid intermediate JSON
    // copies or reallocations that leave discarded password/key bytes behind.
    Text json; json.s.reserve(256 * 1024);
    common(json.s, p, "webdav"); Text password{utf8(p.password)};
    add(json.s, ",\"options\":{\"url\":", p.url); add(json.s, ",\"vendor\":\"other\",\"user\":", p.user);
    add(json.s, "},\"ca_cert_file\":", p.providerCa.u8string()); add(json.s, "}},\"webdav_password\":", password.s);
    return finish(json.s, "}");
}
Bytes oauthProfileSetup(const OAuthProfile &p) {
    if (p.provider != "drive" && p.provider != "onedrive") throw std::runtime_error("请选择支持的云盘服务");
    Text json; json.s.reserve(256 * 1024); common(json.s, p, p.provider); Text secret{utf8(p.clientSecret)};
    add(json.s, ",\"options\":{\"client_id\":", p.clientId); add(json.s, ",\"client_secret\":", secret.s);
    add(json.s, p.provider == "drive" ? ",\"scope\":" : ",\"region\":", p.scopeOrRegion);
    return finish(json.s, "}}}}");
}
Bytes profileMaintenancePatch(const ProfileMaintenance &p) {
    Text json; json.s.reserve(256 * 1024); add(json.s, "{\"action\":", p.action);
    if (p.action == "oauth") {
        if (!p.clientId.empty()) add(json.s, ",\"client_id\":", p.clientId);
        if (!p.clientSecret.empty()) { Text secret{utf8(p.clientSecret)}; add(json.s, ",\"client_secret\":", secret.s); }
    } else if (p.action == "webdav") {
        Text secret{utf8(p.secret)}; add(json.s, ",\"secret\":", secret.s);
        if (!p.providerCa.empty()) add(json.s, ",\"provider_ca_file\":", p.providerCa.u8string());
    } else if (p.action != "coordinator") throw std::runtime_error("请选择支持的云配置更新操作");
    if (p.action == "coordinator" || !p.coordinator.coordinator.empty()) {
        const auto &c = p.coordinator; Text ca{read(c.ca, 65536)}, cert{read(c.certificate, 65536)}, key{read(c.privateKey, 16384)};
        add(json.s, ",\"coordinator\":{\"endpoints\":[", c.coordinator); add(json.s, "],\"ca_pem\":", ca.s);
        add(json.s, ",\"client_cert_pem\":", cert.s); add(json.s, ",\"client_key_pem\":", key.s);
        return finish(json.s, "}}");
    }
    return finish(json.s, "}");
}
}
