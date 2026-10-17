#include "platform.h"
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <mbedtls/platform_util.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#else
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#else
#include <sys/random.h>
#endif
#endif

namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
std::filesystem::path temporaryName(const std::filesystem::path &path) {
    unsigned char nonce[16];
    platform::randomFill(nonce, sizeof(nonce));
    static const char digits[] = "0123456789abcdef";
    std::string suffix = ".";
    for (auto b : nonce) { suffix += digits[b >> 4]; suffix += digits[b & 15]; }
    auto temp = path; temp += suffix + ".tmp"; return temp;
}
}

void secureZero(void *data, size_t size) noexcept { if (data && size) mbedtls_platform_zeroize(data, size); }

// Decode one code point; returns false on malformed, overlong, surrogate or >U+10FFFF.
static bool decodeUtf8(const std::string &s, size_t &i, char32_t &out) {
    auto b = static_cast<unsigned char>(s[i]);
    unsigned extra = b < 0x80 ? 0 : (b & 0xe0) == 0xc0 ? 1 : (b & 0xf0) == 0xe0 ? 2 : (b & 0xf8) == 0xf0 ? 3 : 4;
    if (extra == 4 || i + extra >= s.size() + (extra ? 0 : 1)) return false;
    char32_t c = extra == 0 ? b : extra == 1 ? (b & 0x1f) : extra == 2 ? (b & 0x0f) : (b & 0x07);
    for (unsigned k = 1; k <= extra; ++k) {
        auto n = static_cast<unsigned char>(s[i + k]);
        if ((n & 0xc0) != 0x80) return false;
        c = (c << 6) | (n & 0x3f);
    }
    static const char32_t minimum[] = {0, 0x80, 0x800, 0x10000};
    if (c < minimum[extra] || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return false;
    i += extra + 1; out = c; return true;
}
bool validUtf8(const std::string &s) noexcept {
    for (size_t i = 0; i < s.size();) { char32_t c; if (!decodeUtf8(s, i, c)) return false; }
    return true;
}
std::wstring widen(const std::string &s) {
    std::wstring out; out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        char32_t c; require(decodeUtf8(s, i, c), "UTF-8 decoding failed");
        if (sizeof(wchar_t) == 2 && c >= 0x10000) {
            c -= 0x10000;
            out += static_cast<wchar_t>(0xd800 + (c >> 10)); out += static_cast<wchar_t>(0xdc00 + (c & 0x3ff));
        } else out += static_cast<wchar_t>(c);
    }
    return out;
}
std::string utf8(const std::wstring &s) {
    std::string out; out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char32_t c = static_cast<char32_t>(s[i]);
        if (sizeof(wchar_t) == 2 && c >= 0xd800 && c <= 0xdbff) {
            require(i + 1 < s.size(), "UTF-16 encoding failed");
            char32_t low = static_cast<char32_t>(s[++i]);
            require(low >= 0xdc00 && low <= 0xdfff, "UTF-16 encoding failed");
            c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
        }
        require(c <= 0x10ffff && !(c >= 0xd800 && c <= 0xdfff), "UTF-16 encoding failed");
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) { out += static_cast<char>(0xc0 | (c >> 6)); out += static_cast<char>(0x80 | (c & 0x3f)); }
        else if (c < 0x10000) {
            out += static_cast<char>(0xe0 | (c >> 12)); out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (c & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (c >> 18)); out += static_cast<char>(0x80 | ((c >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3f)); out += static_cast<char>(0x80 | (c & 0x3f));
        }
    }
    return out;
}

void sleepMs(unsigned ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
uint64_t tickMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
std::time_t utcSeconds(const std::tm &utc) {
    std::tm copy = utc;
#ifdef _WIN32
    auto result = _mkgmtime64(&copy);
#else
    auto result = timegm(&copy);
#endif
    require(result >= 0, "证书时间不正确"); return static_cast<std::time_t>(result);
}
std::tm utcTime(std::time_t seconds) {
    std::tm out{};
#ifdef _WIN32
    require(gmtime_s(&out, &seconds) == 0, "时间不正确");
#else
    require(gmtime_r(&seconds, &out) != nullptr, "时间不正确");
#endif
    return out;
}

namespace platform {
void randomFill(void *out, size_t length) {
    auto p = static_cast<unsigned char *>(out);
#ifdef _WIN32
    while (length) {
        auto chunk = static_cast<ULONG>(length > 0x10000000 ? 0x10000000 : length);
        require(BCryptGenRandom(nullptr, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "随机数生成失败");
        p += chunk; length -= chunk;
    }
#elif defined(__APPLE__)
    arc4random_buf(p, length);
#else
    while (length) {
        auto n = getrandom(p, length, 0);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "随机数生成失败");
        p += n; length -= static_cast<size_t>(n);
    }
#endif
}
std::filesystem::path dataDirectory() {
#ifdef _WIN32
    PWSTR p = nullptr;
    require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p)), "无法找到本机数据目录");
    std::filesystem::path path(p); CoTaskMemFree(p);
    return path / L"PicoFido2Remote";
#else
    auto env = [](const char *name) -> std::string { const char *v = std::getenv(name); return v && *v ? v : ""; };
    auto home = env("HOME"); require(!home.empty() && home[0] == '/', "无法找到用户主目录");
#ifdef __APPLE__
    return std::filesystem::path(home) / "Library" / "Application Support" / "PicoFido2Remote";
#else
    auto data = env("XDG_DATA_HOME");
    std::filesystem::path base = !data.empty() && data[0] == '/' ? std::filesystem::path(data) : std::filesystem::path(home) / ".local" / "share";
    return base / "PicoFido2Remote";
#endif
#endif
}
std::filesystem::path executablePath() {
#ifdef _WIN32
    std::wstring path(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(n && n < path.size(), "无法定位程序路径"); path.resize(n); return path;
#elif defined(__APPLE__)
    uint32_t size = 0; _NSGetExecutablePath(nullptr, &size);
    std::string path(size, '\0'); require(_NSGetExecutablePath(path.data(), &size) == 0, "无法定位程序路径");
    path.resize(std::strlen(path.c_str()));
    return std::filesystem::weakly_canonical(path);
#else
    return std::filesystem::read_symlink("/proc/self/exe");
#endif
}
std::string protectedExtension() {
#ifdef _WIN32
    return ".dpapi";
#else
    return ".sealed";
#endif
}

void createPrivateDirectories(const std::filesystem::path &directory) {
#ifdef _WIN32
    std::filesystem::create_directories(directory);
#else
    // Directories created here hold per-user secrets: owner-only. Existing
    // (possibly user-chosen) directories are never changed.
    std::vector<std::filesystem::path> missing;
    for (auto p = directory; !p.empty() && !std::filesystem::exists(p); p = p.parent_path()) {
        missing.push_back(p);
        if (p == p.parent_path()) break;
    }
    std::filesystem::create_directories(directory);
    for (const auto &p : missing) ::chmod(p.c_str(), 0700);
#endif
}

#ifdef _WIN32
namespace {
struct Handle {
    HANDLE h;
    explicit Handle(HANDLE v) : h(v) {}
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
}
Bytes readFile(const std::filesystem::path &path, size_t maximum, const char *error) {
    Handle f(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    require(f.h != INVALID_HANDLE_VALUE, error);
    LARGE_INTEGER size{};
    require(GetFileSizeEx(f.h, &size) && size.QuadPart > 0 && static_cast<uint64_t>(size.QuadPart) <= maximum, error);
    Bytes b(static_cast<size_t>(size.QuadPart)); DWORD n = 0;
    require(ReadFile(f.h, b.data(), static_cast<DWORD>(b.size()), &n, nullptr) && n == b.size(), error);
    return b;
}
void writeNewFile(const std::filesystem::path &path, const Bytes &bytes, const char *error) {
    Handle f(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    require(f.h != INVALID_HANDLE_VALUE, error);
    DWORD n = 0;
    require(WriteFile(f.h, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr) && n == bytes.size() &&
        FlushFileBuffers(f.h), error);
}
void publishFile(const std::filesystem::path &path, const Bytes &bytes, bool replace, const char *error,
                 const std::function<void()> &beforePublish) {
    auto temp = temporaryName(path);
    struct Cleanup { std::filesystem::path p; ~Cleanup() { DeleteFileW(p.c_str()); } } cleanup{temp};
    writeNewFile(temp, bytes, error);
    if (beforePublish) beforePublish();
    require(MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0)), error);
}
void removeFile(const std::filesystem::path &path) noexcept { DeleteFileW(path.c_str()); }
void removeFileChecked(const std::filesystem::path &path, const char *error) { require(DeleteFileW(path.c_str()) != FALSE, error); }

FileLock::FileLock(const std::filesystem::path &path, Mode mode, const char *error) {
    DWORD disposition = mode == Mode::CreateNew ? CREATE_NEW : mode == Mode::OpenExisting ? OPEN_EXISTING : OPEN_ALWAYS;
    // Share mode 0: no other process can open the marker while it is held.
    handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    auto last = GetLastError();
    require(handle != INVALID_HANDLE_VALUE, error);
    wasCreated = mode == Mode::CreateNew || (mode == Mode::OpenAlways && last != ERROR_ALREADY_EXISTS);
}
void FileLock::close() noexcept { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); handle = INVALID_HANDLE_VALUE; }
bool FileLock::valid() const { return handle != INVALID_HANDLE_VALUE; }
uint64_t FileLock::size() const {
    LARGE_INTEGER size{}; require(GetFileSizeEx(handle, &size), "无法读取锁文件"); return static_cast<uint64_t>(size.QuadPart);
}
Bytes FileLock::read(size_t length) const {
    LARGE_INTEGER start{}; Bytes out(length); DWORD n = 0;
    require(SetFilePointerEx(handle, start, nullptr, FILE_BEGIN) &&
        ReadFile(handle, out.data(), static_cast<DWORD>(length), &n, nullptr) && n == length, "无法读取锁文件");
    return out;
}
void FileLock::write(const Bytes &bytes) const {
    LARGE_INTEGER start{}; DWORD n = 0;
    require(SetFilePointerEx(handle, start, nullptr, FILE_BEGIN) &&
        WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr) && n == bytes.size() &&
        FlushFileBuffers(handle), "无法写入锁文件");
}
bool fidoAccessRequiresElevation() { return true; }
bool isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{}; DWORD size = 0;
    bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE;
    CloseHandle(token); return ok && elevation.TokenIsElevated;
}
#else
namespace {
struct Fd {
    int fd;
    explicit Fd(int v) : fd(v) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
};
bool fullWrite(int fd, const unsigned char *p, size_t n) {
    while (n) {
        auto w = ::write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w; n -= static_cast<size_t>(w);
    }
    return true;
}
bool fullRead(int fd, unsigned char *p, size_t n) {
    while (n) {
        auto r = ::read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}
void syncDirectory(const std::filesystem::path &path) {
    auto parent = path.parent_path(); if (parent.empty()) parent = ".";
    Fd dir(::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (dir.fd >= 0) ::fsync(dir.fd);
}
}
// Atomic publication that fails when the destination exists.
bool renameNoReplace(const std::filesystem::path &from, const std::filesystem::path &to) {
#if defined(__APPLE__)
    if (::renamex_np(from.c_str(), to.c_str(), RENAME_EXCL) == 0) return true;
#elif defined(RENAME_NOREPLACE)
    if (::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), RENAME_NOREPLACE) == 0) return true;
#endif
    if (errno == EEXIST) return false;
    if (::link(from.c_str(), to.c_str()) == 0) return true;
    return false;
}
Bytes readFile(const std::filesystem::path &path, size_t maximum, const char *error) {
    Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC)); // user-chosen imports may be symlinks
    require(f.fd >= 0, error);
    struct stat st{}; require(::fstat(f.fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        static_cast<uint64_t>(st.st_size) <= maximum, error);
    Bytes b(static_cast<size_t>(st.st_size)); require(fullRead(f.fd, b.data(), b.size()), error);
    return b;
}
void writeNewFile(const std::filesystem::path &path, const Bytes &bytes, const char *error) {
    Fd f(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    require(f.fd >= 0, error);
    require(fullWrite(f.fd, bytes.data(), bytes.size()) && ::fsync(f.fd) == 0, error);
}
void publishFile(const std::filesystem::path &path, const Bytes &bytes, bool replace, const char *error,
                 const std::function<void()> &beforePublish) {
    auto temp = temporaryName(path);
    struct Cleanup { std::filesystem::path p; ~Cleanup() { ::unlink(p.c_str()); } } cleanup{temp};
    writeNewFile(temp, bytes, error);
    if (beforePublish) beforePublish();
    if (replace) require(::rename(temp.c_str(), path.c_str()) == 0, error);
    else if (!renameNoReplace(temp, path)) {
        // Filesystems without an atomic no-replace rename or hard links (FAT,
        // exFAT, SMB): create the destination exclusively and write it directly.
        require(errno == EPERM || errno == ENOTSUP || errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP, error);
        writeNewFile(path, bytes, error);
    }
    syncDirectory(path);
}
void removeFile(const std::filesystem::path &path) noexcept { ::unlink(path.c_str()); }
void removeFileChecked(const std::filesystem::path &path, const char *error) {
    require(::unlink(path.c_str()) == 0, error); syncDirectory(path);
}

FileLock::FileLock(const std::filesystem::path &path, Mode mode, const char *error) {
    int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
    if (mode == Mode::CreateNew) flags |= O_CREAT | O_EXCL;
    fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0 && mode == Mode::OpenAlways && errno == ENOENT) {
        fd = ::open(path.c_str(), flags | O_CREAT | O_EXCL, 0600);
        wasCreated = fd >= 0;
        if (fd < 0 && errno == EEXIST) fd = ::open(path.c_str(), flags);
    } else wasCreated = mode == Mode::CreateNew && fd >= 0;
    require(fd >= 0, error);
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) { close(); throw std::runtime_error(error); }
    if (wasCreated) syncDirectory(path);
}
void FileLock::close() noexcept { if (fd >= 0) ::close(fd); fd = -1; }
bool FileLock::valid() const { return fd >= 0; }
uint64_t FileLock::size() const {
    struct stat st{}; require(::fstat(fd, &st) == 0, "无法读取锁文件"); return static_cast<uint64_t>(st.st_size);
}
Bytes FileLock::read(size_t length) const {
    Bytes out(length);
    require(::lseek(fd, 0, SEEK_SET) == 0 && fullRead(fd, out.data(), length), "无法读取锁文件");
    return out;
}
void FileLock::write(const Bytes &bytes) const {
    require(::lseek(fd, 0, SEEK_SET) == 0 && fullWrite(fd, bytes.data(), bytes.size()) && ::fsync(fd) == 0, "无法写入锁文件");
}
bool fidoAccessRequiresElevation() { return false; }
bool isElevated() { return ::geteuid() == 0; }
#endif
FileLock::~FileLock() { close(); }
FileLock::FileLock(FileLock &&other) noexcept { *this = std::move(other); }
FileLock &FileLock::operator=(FileLock &&other) noexcept {
    if (this != &other) {
        close();
#ifdef _WIN32
        handle = other.handle; other.handle = INVALID_HANDLE_VALUE;
#else
        fd = other.fd; other.fd = -1;
#endif
        wasCreated = other.wasCreated;
    }
    return *this;
}
}
