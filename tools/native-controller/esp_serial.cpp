// System serial ports for esp_flasher: finding the ESP32-S3 ROM's USB device and
// raw byte I/O with DTR/RTS control.
#include "esp_flasher.h"
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <initguid.h>
#include <devguid.h>
#include <setupapi.h>
#include <cwctype>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#elif !defined(_WIN32)
#include <fstream>
#endif

namespace esp {
namespace {
constexpr unsigned RomVendor = 0x303a, RomProduct = 0x1001; // ESP32-S3 ROM USB serial/JTAG
const char *const openError = "无法打开下载模式设备的串口（可能被其他程序占用）";

#ifdef _WIN32
class Serial : public Link {
    HANDLE h;
public:
    explicit Serial(const std::string &path) {
        h = CreateFileW(widen(path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) throw std::runtime_error(openError);
        DCB dcb{}; dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(h, &dcb)) { CloseHandle(h); throw std::runtime_error(openError); }
        dcb.BaudRate = 115200; dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT; dcb.fBinary = TRUE;
        dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = dcb.fOutX = dcb.fInX = FALSE;
        dcb.fDtrControl = DTR_CONTROL_ENABLE; dcb.fRtsControl = RTS_CONTROL_ENABLE;
        if (!SetCommState(h, &dcb)) { CloseHandle(h); throw std::runtime_error(openError); }
        PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    }
    ~Serial() override { CloseHandle(h); }
    void write(const uint8_t *data, size_t size) override {
        COMMTIMEOUTS t{}; t.WriteTotalTimeoutConstant = 3000; SetCommTimeouts(h, &t);
        DWORD n = 0;
        if (!WriteFile(h, data, static_cast<DWORD>(size), &n, nullptr) || n != size) throw std::runtime_error("向设备发送数据失败，设备可能已断开");
    }
    size_t read(uint8_t *data, size_t size, int timeoutMs) override {
        // Return as soon as any byte arrives, or after the timeout.
        COMMTIMEOUTS t{}; t.ReadIntervalTimeout = MAXDWORD; t.ReadTotalTimeoutMultiplier = MAXDWORD;
        t.ReadTotalTimeoutConstant = static_cast<DWORD>(timeoutMs > 0 ? timeoutMs : 1); SetCommTimeouts(h, &t);
        DWORD n = 0;
        if (!ReadFile(h, data, static_cast<DWORD>(size), &n, nullptr)) throw std::runtime_error("从设备读取数据失败，设备可能已断开");
        return n;
    }
    void lines(bool dtr, bool rts) override { // one SetCommState changes both lines together
        DCB dcb{}; dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(h, &dcb)) return;
        dcb.fDtrControl = dtr ? DTR_CONTROL_ENABLE : DTR_CONTROL_DISABLE;
        dcb.fRtsControl = rts ? RTS_CONTROL_ENABLE : RTS_CONTROL_DISABLE;
        SetCommState(h, &dcb);
    }
};
#else
class Serial : public Link {
    int fd;
public:
    explicit Serial(const std::string &path) {
        fd = ::open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error(openError);
        termios t{};
        if (::ioctl(fd, TIOCEXCL) != 0 || ::tcgetattr(fd, &t) != 0) { ::close(fd); throw std::runtime_error(openError); }
        ::cfmakeraw(&t); ::cfsetspeed(&t, B115200);
        t.c_cflag |= CLOCAL | CREAD; t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
        if (::tcsetattr(fd, TCSANOW, &t) != 0) { ::close(fd); throw std::runtime_error(openError); }
        ::tcflush(fd, TCIOFLUSH);
    }
    ~Serial() override { ::close(fd); }
    void write(const uint8_t *data, size_t size) override {
        while (size) {
            auto n = ::write(fd, data, size);
            if (n > 0) { data += n; size -= static_cast<size_t>(n); continue; }
            pollfd p{fd, POLLOUT, 0};
            if ((n < 0 && errno != EAGAIN && errno != EINTR) || ::poll(&p, 1, 3000) <= 0)
                throw std::runtime_error("向设备发送数据失败，设备可能已断开");
        }
    }
    size_t read(uint8_t *data, size_t size, int timeoutMs) override {
        pollfd p{fd, POLLIN, 0};
        int r = ::poll(&p, 1, timeoutMs);
        if (r < 0 && errno == EINTR) return 0;
        if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) throw std::runtime_error("从设备读取数据失败，设备可能已断开");
        if (r == 0) return 0;
        auto n = ::read(fd, data, size);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
        if (n <= 0) throw std::runtime_error("从设备读取数据失败，设备可能已断开");
        return static_cast<size_t>(n);
    }
    void lines(bool dtr, bool rts) override { // TIOCMSET changes both lines together
        int bits = 0;
        if (::ioctl(fd, TIOCMGET, &bits) != 0) return;
        bits = (bits & ~(TIOCM_DTR | TIOCM_RTS)) | (dtr ? TIOCM_DTR : 0) | (rts ? TIOCM_RTS : 0);
        ::ioctl(fd, TIOCMSET, &bits);
    }
};
#endif

#ifdef __APPLE__
unsigned number(io_object_t service, CFStringRef key) {
    auto value = IORegistryEntrySearchCFProperty(service, kIOServicePlane, key, kCFAllocatorDefault,
                                                 kIORegistryIterateRecursively | kIORegistryIterateParents);
    int result = 0;
    if (value) {
        if (CFGetTypeID(value) == CFNumberGetTypeID()) CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberIntType, &result);
        CFRelease(value);
    }
    return static_cast<unsigned>(result);
}
#endif
}

std::vector<DownloadPort> downloadPorts() {
    std::vector<DownloadPort> ports;
#ifdef _WIN32
    auto set = SetupDiGetClassDevsW(&GUID_DEVCLASS_PORTS, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return ports;
    SP_DEVINFO_DATA info{}; info.cbSize = sizeof(info);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &info); ++i) {
        wchar_t id[512];
        if (!SetupDiGetDeviceInstanceIdW(set, &info, id, 512, nullptr)) continue;
        std::wstring upper(id);
        for (auto &c : upper) c = static_cast<wchar_t>(std::towupper(c));
        if (upper.find(L"VID_303A&PID_1001") == std::wstring::npos) continue;
        auto key = SetupDiOpenDevRegKey(set, &info, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (key == INVALID_HANDLE_VALUE) continue;
        wchar_t name[64] = {}; DWORD size = sizeof(name) - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(key, L"PortName", nullptr, &type, reinterpret_cast<BYTE *>(name), &size) == ERROR_SUCCESS && type == REG_SZ)
            ports.push_back({utf8(L"\\\\.\\" + std::wstring(name)), utf8(name)});
        RegCloseKey(key);
    }
    SetupDiDestroyDeviceInfoList(set);
#elif defined(__APPLE__)
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(MACH_PORT_NULL, IOServiceMatching(kIOSerialBSDServiceValue), &it) != KERN_SUCCESS) return ports;
    while (io_object_t service = IOIteratorNext(it)) {
        if (number(service, CFSTR("idVendor")) == RomVendor && number(service, CFSTR("idProduct")) == RomProduct) {
            auto path = static_cast<CFStringRef>(IORegistryEntryCreateCFProperty(service, CFSTR(kIOCalloutDeviceKey), kCFAllocatorDefault, 0));
            char text[256];
            if (path && CFGetTypeID(path) == CFStringGetTypeID() && CFStringGetCString(path, text, sizeof(text), kCFStringEncodingUTF8))
                ports.push_back({text, text});
            if (path) CFRelease(path);
        }
        IOObjectRelease(service);
    }
    IOObjectRelease(it);
#else
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator("/sys/class/tty", ec)) {
        auto name = entry.path().filename().string();
        if (name.rfind("ttyACM", 0) != 0) continue;
        auto read = [&](const char *file) {
            std::ifstream in(entry.path() / "device" / ".." / file); unsigned v = 0; in >> std::hex >> v; return v;
        };
        if (read("idVendor") == RomVendor && read("idProduct") == RomProduct) ports.push_back({"/dev/" + name, "/dev/" + name});
    }
#endif
    return ports;
}
std::unique_ptr<Link> openSerial(const std::string &path) { return std::make_unique<Serial>(path); }

}
