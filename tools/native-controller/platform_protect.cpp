#include "platform.h"
#include "crypto.h"
#include <chrono>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#else
#include <libsecret/secret.h>
#endif

// Windows uses DPAPI directly (format unchanged from earlier releases). Other
// systems keep one random 256-bit key per user in the OS keyring and seal files
// with AES-256-GCM: "PF2SEAL1" | nonce[12] | ciphertext | tag[16], where the
// magic and purpose label are authenticated. A missing keyring fails closed.
namespace platform {
namespace {
[[noreturn]] void fail(const char *message) { throw std::runtime_error(message); }
#ifndef _WIN32
constexpr unsigned char sealMagic[8] = {'P', 'F', '2', 'S', 'E', 'A', 'L', '1'};
constexpr const char *keyringService = "PicoFido2Remote";
constexpr const char *keyringAccount = "data-protection-key-v1";
const char *keyringError = "无法访问系统钥匙串；本机加密数据不可用";

Bytes decodeHex(const std::string &text) {
    auto digit = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    Bytes out;
    if (text.size() != 64) return out;
    for (size_t i = 0; i < 64; i += 2) {
        int hi = digit(text[i]), lo = digit(text[i + 1]);
        if (hi < 0 || lo < 0) { wipe(out); return {}; }
        out.push_back(static_cast<unsigned char>(hi << 4 | lo));
    }
    return out;
}
std::string encodeHex(const Bytes &b) {
    static const char digits[] = "0123456789abcdef"; std::string s;
    for (auto c : b) { s += digits[c >> 4]; s += digits[c & 15]; }
    return s;
}
#ifdef __APPLE__
struct Ref {
    CFTypeRef p = nullptr;
    ~Ref() { if (p) CFRelease(p); }
};
CFMutableDictionaryRef query() {
    auto q = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!q) fail(keyringError);
    Ref service{CFStringCreateWithCString(nullptr, keyringService, kCFStringEncodingUTF8)};
    Ref account{CFStringCreateWithCString(nullptr, keyringAccount, kCFStringEncodingUTF8)};
    if (!service.p || !account.p) { CFRelease(q); fail(keyringError); }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, service.p);
    CFDictionarySetValue(q, kSecAttrAccount, account.p);
    return q;
}
bool loadSecret(std::string &out) {
    Ref q{query()}; auto dict = (CFMutableDictionaryRef)q.p;
    CFDictionarySetValue(dict, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(dict, kSecMatchLimit, kSecMatchLimitOne);
    Ref data;
    OSStatus status = SecItemCopyMatching(dict, &data.p);
    if (status == errSecItemNotFound) return false;
    if (status != errSecSuccess || !data.p || CFGetTypeID(data.p) != CFDataGetTypeID()) fail(keyringError);
    auto bytes = (CFDataRef)data.p;
    out.assign(reinterpret_cast<const char *>(CFDataGetBytePtr(bytes)), static_cast<size_t>(CFDataGetLength(bytes)));
    return true;
}
void storeSecret(const std::string &value) {
    Ref q{query()}; auto dict = (CFMutableDictionaryRef)q.p;
    Ref data{CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(value.data()), static_cast<CFIndex>(value.size()))};
    if (!data.p) fail(keyringError);
    CFDictionarySetValue(dict, kSecValueData, data.p);
    // The login (file-based) keychain trusts only the creating binary by default,
    // so every other or rebuilt unsigned executable would block on an access
    // prompt. Like Secret Service and DPAPI, let any process of this user read
    // the key without prompting. (The data-protection keychain would need a
    // provisioned app identifier.)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Ref label{CFStringCreateWithCString(nullptr, "Pico FIDO2 controller data key", kCFStringEncodingUTF8)};
    Ref access;
    if (!label.p || SecAccessCreate((CFStringRef)label.p, nullptr, (SecAccessRef *)&access.p) != errSecSuccess) fail(keyringError);
    Ref acls{SecAccessCopyMatchingACLList((SecAccessRef)access.p, kSecACLAuthorizationDecrypt)};
    if (!acls.p || CFArrayGetCount((CFArrayRef)acls.p) == 0) fail(keyringError);
    for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)acls.p); ++i) {
        auto acl = (SecACLRef)CFArrayGetValueAtIndex((CFArrayRef)acls.p, i);
        if (SecACLSetContents(acl, nullptr, (CFStringRef)label.p, 0) != errSecSuccess) fail(keyringError);
    }
#pragma clang diagnostic pop
    CFDictionarySetValue(dict, kSecAttrAccess, access.p);
    CFDictionarySetValue(dict, kSecAttrLabel, label.p);
    OSStatus status = SecItemAdd(dict, nullptr);
    if (status != errSecSuccess && status != errSecDuplicateItem) fail(keyringError);
}
#else
const SecretSchema *schema() {
    static const SecretSchema value = {
        "org.picofido2.remote.DataProtection", SECRET_SCHEMA_NONE,
        {{"account", SECRET_SCHEMA_ATTRIBUTE_STRING}, {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}, 0, 0, 0, 0, 0, 0, 0, 0};
    return &value;
}
bool loadSecret(std::string &out) {
    GError *error = nullptr;
    gchar *value = secret_password_lookup_sync(schema(), nullptr, &error, "account", keyringAccount, nullptr);
    if (error) { g_error_free(error); if (value) secret_password_free(value); fail(keyringError); }
    if (!value) return false;
    out = value; secret_password_free(value); // secret_password_free wipes the buffer.
    return true;
}
void storeSecret(const std::string &value) {
    GError *error = nullptr;
    gboolean ok = secret_password_store_sync(schema(), SECRET_COLLECTION_DEFAULT, "Pico FIDO2 controller data key",
        value.c_str(), nullptr, &error, "account", keyringAccount, nullptr);
    if (error) g_error_free(error);
    if (!ok) fail(keyringError);
}
#endif
Bytes loadDataKey(bool create) {
    std::string stored;
    if (!loadSecret(stored)) {
        if (!create) fail("系统钥匙串中没有本机数据密钥；无法解密已有数据");
        // Secret Service "store" replaces an existing item. Serialize creation
        // across threads and processes, then re-check before generating.
        static std::mutex mutex; std::lock_guard<std::mutex> guard(mutex);
        createPrivateDirectories(dataDirectory());
        FileLock lock;
        for (int i = 0;; ++i) {
            try { lock = FileLock(dataDirectory() / ".protection-key.lock", FileLock::Mode::OpenAlways, keyringError); break; }
            catch (...) { if (i >= 100) throw; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
        }
        if (!loadSecret(stored)) {
            auto fresh = crypto::randomBytes(32); auto text = encodeHex(fresh); wipe(fresh);
            storeSecret(text); wipe(text);
            if (!loadSecret(stored)) fail(keyringError);
        }
    }
    auto key = decodeHex(stored); wipe(stored);
    if (key.size() != 32) fail("系统钥匙串中的本机数据密钥已损坏");
    return key;
}
// Keyring lookups are IPC round trips (securityd, D-Bus) that cost tens of
// milliseconds each, so keep the key for the life of the process once read.
Bytes dataKey(bool create) {
    static std::mutex mutex; static Bytes cached;
    std::lock_guard<std::mutex> guard(mutex);
    if (cached.empty()) cached = loadDataKey(create);
    return cached;
}
Bytes aad(const char *purpose) {
    Bytes out(std::begin(sealMagic), std::end(sealMagic));
    out.insert(out.end(), purpose, purpose + std::strlen(purpose));
    return out;
}
#endif
}
Bytes protect(const Bytes &plain, const char *purpose) {
#ifdef _WIN32
    auto label = widen(purpose);
    DATA_BLOB in{static_cast<DWORD>(plain.size()), const_cast<BYTE *>(plain.data())}, out{};
    if (!CryptProtectData(&in, label.c_str(), nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        fail("Windows 无法加密本机数据");
    Bytes result(out.pbData, out.pbData + out.cbData);
    secureZero(out.pbData, out.cbData); LocalFree(out.pbData);
    return result;
#else
    auto key = dataKey(true);
    auto nonce = crypto::randomBytes(12); unsigned char tag[16];
    Bytes body;
    try { body = crypto::gcmEncrypt(key, nonce.data(), aad(purpose), plain.data(), plain.size(), tag); }
    catch (...) { wipe(key); throw; }
    wipe(key);
    Bytes out(std::begin(sealMagic), std::end(sealMagic));
    out.insert(out.end(), nonce.begin(), nonce.end()); out.insert(out.end(), body.begin(), body.end());
    out.insert(out.end(), tag, tag + 16);
    return out;
#endif
}
Bytes unprotect(const Bytes &sealed, const char *purpose) {
#ifdef _WIN32
    (void)purpose;
    DATA_BLOB in{static_cast<DWORD>(sealed.size()), const_cast<BYTE *>(sealed.data())}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        fail("Windows 无法解密本机数据；请使用创建它的 Windows 用户");
    Bytes result(out.pbData, out.pbData + out.cbData);
    secureZero(out.pbData, out.cbData); LocalFree(out.pbData);
    return result;
#else
    const char *error = "无法解密本机数据；文件已损坏或属于其他用户";
    if (sealed.size() < 8 + 12 + 16 || std::memcmp(sealed.data(), sealMagic, 8)) fail(error);
    auto key = dataKey(false);
    Bytes plain;
    try {
        plain = crypto::gcmDecrypt(key, sealed.data() + 8, aad(purpose), sealed.data() + 20, sealed.size() - 36,
            sealed.data() + sealed.size() - 16, error);
    } catch (...) { wipe(key); throw; }
    wipe(key);
    return plain;
#endif
}
}
