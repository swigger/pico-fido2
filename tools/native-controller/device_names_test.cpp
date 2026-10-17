#include "device_names.h"
#include <cstdio>
#include <fstream>
#include <stdexcept>

static void check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}
template<class F> static void rejects(F f) {
    bool rejected = false;
    try { f(); } catch (const std::exception &) { rejected = true; }
    check(rejected, "invalid input accepted");
}
int main() {
    const auto nonce = randomBytes(12);
    const auto dir = std::filesystem::temp_directory_path() / ("pf2-name-test-" + hex(nonce.data(), nonce.size()));
    try {
        check(validDeviceSerial("0123456789aBcDeF"), "valid serial rejected");
        check(!validDeviceSerial("../../controller"), "path accepted as serial");
        validateDeviceName(std::wstring(32, L'a'));
        validateDeviceName(L"中文名称测试十个汉字ab"); // ten CJK code points + two ASCII = 32 bytes
        validateDeviceName(L"😀😀😀😀😀😀😀😀"); // eight supplementary characters = 32 bytes
        rejects([] { validateDeviceName(std::wstring(33, L'a')); });
        rejects([] { validateDeviceName(L"中文名称测试十个汉字abc"); });
        rejects([] { validateDeviceName(L"😀😀😀😀😀😀😀😀a"); });
        rejects([] { validateDeviceName(std::wstring(1, wchar_t(0xd800))); });
        rejects([] { validateDeviceName(L"line\nbreak"); });
        rejects([] { validateDeviceName(L"hidden\u202Ename"); });
        rejects([] { validateDeviceName(std::wstring(L"a\0b", 3)); });
        rejects([&] { saveDeviceName("../../controller", L"invalid", dir); });
        const std::string a = "0011223344556677", b = "8899AABBCCDDEEFF";
        check(loadDeviceName(a, dir).empty(), "missing name");
        saveDeviceName(a, L"办公室钥匙", dir);
        saveDeviceName(b, L"随身备用", dir);
        check(loadDeviceName(a, dir) == L"办公室钥匙", "name persistence");
        check(loadDeviceName("8899aabbccddeeff", dir) == L"随身备用", "serial normalization");
        rejects([&] { saveDeviceName(a, std::wstring(33, L'x'), dir); });
        check(loadDeviceName(a, dir) == L"办公室钥匙", "invalid edit changed name");
        saveDeviceName(a, L"", dir);
        check(loadDeviceName(a, dir).empty(), "clear name");
        check(loadDeviceName(b, dir) == L"随身备用", "clear affected other key");
        {
            std::ofstream corrupt(dir / "0011223344556677.name", std::ios::binary);
            corrupt << "\xff";
        }
        rejects([&] { loadDeviceName(a, dir); });
        // Remove only files created in this unique test directory; no recursive deletion.
        for (const auto &entry : std::filesystem::directory_iterator(dir)) std::filesystem::remove(entry.path());
        std::filesystem::remove(dir);
        puts("PASS: UTF-8 byte limits, invalid names/serials, persistence, independent devices and corrupt metadata");
        return 0;
    } catch (const std::exception &e) {
        fprintf(stderr, "FAIL: %s (test directory: %s)\n", e.what(), dir.u8string().c_str());
        return 1;
    }
}
