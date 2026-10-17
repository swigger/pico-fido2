#include "relay_backup.h"
#include <algorithm>
#include <cwchar>
#include <stdexcept>

namespace relay::backup {
namespace {
constexpr uint32_t iterations = 600000;
constexpr size_t headerSize = 60;
const unsigned char magic[8] = {'P','F','2','B','A','K','0','1'};
void need(bool ok, const char *message = "备份密码不正确或文件已损坏") {
    if (!ok) throw std::runtime_error(message);
}
struct Secret {
    Bytes b;
    ~Secret() { if (!b.empty()) secureZero(b.data(), b.size()); }
};
void put(Bytes &b, size_t pos, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) b[pos + i] = static_cast<uint8_t>(value >> (8 * i));
}
uint32_t get(const Bytes &b, size_t pos) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= uint32_t(b[pos + i]) << (8 * i);
    return value;
}
Bytes derive(const std::wstring &password, const Bytes &header) {
    // Bound KDF input and validate Unicode without silently normalizing passwords.
    need(!password.empty() && password.size() <= 512 && password.find(L'\0') == std::wstring::npos,
        "备份密码需要 12–256 个 Unicode 字符");
    auto text = utf8(password);
    struct Clear { std::string &s; ~Clear() { if (!s.empty()) secureZero(s.data(), s.size()); } } clear{text};
    auto characters = std::count_if(text.begin(), text.end(), [](unsigned char c) { return (c & 0xc0) != 0x80; });
    need(characters >= 12 && characters <= 256, "备份密码需要 12–256 个 Unicode 字符");
    return crypto::pbkdf2Sha256(reinterpret_cast<const unsigned char *>(text.data()), text.size(), header.data() + 12, 32,
        iterations, 32);
}
Bytes crypt(const Bytes &input, const std::wstring &password, bool encrypting) {
    Bytes header(headerSize), tag(16);
    size_t size;
    if (encrypting) {
        need(input.size() >= 36 && input.size() <= maxPlaintext, "凭证库备份大小超限"); size = input.size();
        std::copy(std::begin(magic), std::end(magic), header.begin()); put(header, 8, iterations);
        auto rng = randomBytes(44); std::copy(rng.begin(), rng.end(), header.begin() + 12);
        put(header, 56, static_cast<uint32_t>(size));
    } else {
        need(input.size() >= overhead + 36 && input.size() <= maxPlaintext + overhead &&
            std::equal(std::begin(magic), std::end(magic), input.begin()), "不是受支持的安全端凭证库备份");
        std::copy_n(input.begin(), headerSize, header.begin()); size = get(header, 56);
        need(get(header, 8) == iterations && size >= 36 && size <= maxPlaintext && size + overhead == input.size(),
            "备份头部、大小或算法版本不正确");
        std::copy(input.end() - 16, input.end(), tag.begin());
    }
    Secret key{derive(password, header)}, data;
    if (!encrypting) {
        try {
            data.b = crypto::gcmDecrypt(key.b, header.data() + 44, header, input.data() + headerSize, size, tag.data(),
                "备份密码不正确或文件已损坏");
        } catch (const crypto::AuthenticationError &e) { throw PasswordError(e.what()); }
        return std::move(data.b);
    }
    data.b = crypto::gcmEncrypt(key.b, header.data() + 44, header, input.data(), size, tag.data());
    header.insert(header.end(), data.b.begin(), data.b.end()); header.insert(header.end(), tag.begin(), tag.end());
    return header;
}
}
Bytes encrypt(const Bytes &plain, const std::wstring &password) { return crypt(plain, password, true); }
Bytes decrypt(const Bytes &encrypted, const std::wstring &password) { return crypt(encrypted, password, false); }
namespace {
const wchar_t alphabet[] = L"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr size_t codeLength = 26;
}
std::wstring newRecoveryCode() {
    Secret random{crypto::randomBytes(16)};
    std::wstring code; unsigned buffer = 0, bits = 0;
    for (auto byte : random.b) {
        buffer = (buffer << 8) | byte; bits += 8;
        while (bits >= 5) { bits -= 5; code.push_back(alphabet[(buffer >> bits) & 31]); }
    }
    code.push_back(alphabet[(buffer << (5 - bits)) & 31]); // final 3 bits, zero padded
    buffer = 0; return code;
}
std::wstring recoveryCode(const std::wstring &typed) {
    std::wstring code;
    for (auto c : typed) {
        if (c == L' ' || c == L'-' || c == L'\t') continue;
        if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
        if (c == L'I' || c == L'L') c = L'1';
        if (c == L'O') c = L'0';
        need(std::wcschr(alphabet, c) != nullptr && c != 0 && code.size() < codeLength, "恢复码格式不正确：应为 26 个字母或数字");
        code.push_back(c);
    }
    need(code.size() == codeLength, "恢复码格式不正确：应为 26 个字母或数字");
    return code;
}
std::wstring displayRecoveryCode(const std::wstring &code) {
    std::wstring out;
    for (size_t i = 0; i < code.size(); ++i) { if (i && i % 5 == 0 && i < 25) out.push_back(L'-'); out.push_back(code[i]); }
    return out;
}
}
