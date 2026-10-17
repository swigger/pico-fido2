#pragma once
// Operating-system boundary for the controller core. Everything above this layer
// is portable C++17; Windows, macOS and Linux differences live in platform*.cpp.
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

void secureZero(void *data, size_t size) noexcept;
inline void wipe(Bytes &b) noexcept { if (!b.empty()) secureZero(b.data(), b.size()); b.clear(); }
inline void wipe(std::string &s) noexcept { if (!s.empty()) secureZero(s.data(), s.size()); s.clear(); }
inline void wipe(std::wstring &s) noexcept { if (!s.empty()) secureZero(s.data(), s.size() * sizeof(wchar_t)); s.clear(); }

// Strict UTF-8 <-> wchar_t (UTF-16 on Windows, UTF-32 elsewhere). Invalid input throws.
std::wstring widen(const std::string &s);
std::string utf8(const std::wstring &s);
bool validUtf8(const std::string &s) noexcept;

void sleepMs(unsigned milliseconds);
uint64_t tickMs(); // Monotonic milliseconds.
std::time_t utcSeconds(const std::tm &utc); // timegm; throws on failure
std::tm utcTime(std::time_t seconds);       // gmtime; throws on failure

namespace platform {
void randomFill(void *out, size_t length); // OS CSPRNG; throws on failure.
// Per-user application data: %LOCALAPPDATA%, ~/Library/Application Support or
// $XDG_DATA_HOME, each with a PicoFido2Remote subdirectory.
std::filesystem::path dataDirectory();
std::filesystem::path executablePath();
// ".dpapi" on Windows (DPAPI blobs), ".sealed" elsewhere (keyring-sealed AES-GCM).
std::string protectedExtension();
// Bind secrets to the current OS user. The purpose label separates file kinds.
Bytes protect(const Bytes &plain, const char *purpose);
Bytes unprotect(const Bytes &sealed, const char *purpose);

void createPrivateDirectories(const std::filesystem::path &directory);
Bytes readFile(const std::filesystem::path &path, size_t maximum, const char *error);
// Create a new file (never replacing), write and flush it.
void writeNewFile(const std::filesystem::path &path, const Bytes &bytes, const char *error);
// Write a flushed temporary file and atomically move it into place. Without
// replace, publication fails if the destination already exists.
void publishFile(const std::filesystem::path &path, const Bytes &bytes, bool replace, const char *error,
                 const std::function<void()> &beforePublish = {});
void removeFile(const std::filesystem::path &path) noexcept;
// Delete exactly one file, reporting failures (never recursively remove a directory).
void removeFileChecked(const std::filesystem::path &path, const char *error);

// An exclusive, process-wide ownership lock on a small marker file. The lock
// lasts for the object's lifetime; other owners fail immediately, never wait.
class FileLock {
public:
    enum class Mode { CreateNew, OpenExisting, OpenAlways };
    FileLock() = default;
    FileLock(const std::filesystem::path &path, Mode mode, const char *error);
    ~FileLock();
    FileLock(FileLock &&other) noexcept;
    FileLock &operator=(FileLock &&other) noexcept;
    FileLock(const FileLock &) = delete;
    FileLock &operator=(const FileLock &) = delete;
    bool valid() const;
    bool created() const { return wasCreated; }
    uint64_t size() const;
    Bytes read(size_t length) const;          // From offset 0.
    void write(const Bytes &bytes) const;     // At offset 0, then flushed.
private:
#ifdef _WIN32
    void *handle = reinterpret_cast<void *>(-1);
#else
    int fd = -1;
#endif
    bool wasCreated = false;
    void close() noexcept;
};

// Windows restricts raw FIDO HID to elevated processes. Other systems use
// device permissions (udev rules on Linux) and need no elevation.
bool fidoAccessRequiresElevation();
bool isElevated();
}
