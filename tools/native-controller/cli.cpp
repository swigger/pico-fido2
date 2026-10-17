#include "cli.h"
#include "core.h"
#include "credentials.h"
#include "device_names.h"
#include "esp_flasher.h"
#include "relay_backup.h"
#include "relay_control.h"
#include "relay_settings.h"
#include "relay_server.h"
#include <cstdio>
#include <exception>
#include <thread>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace {
#ifdef _WIN32
BOOL WINAPI interrupt(DWORD event) { return event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT; }
struct Terminal {
    HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    HANDLE output = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD previous = 0; bool changed = false, handler = false;
    int exceptions = std::uncaught_exceptions();
    Terminal() {
        AttachConsole(ATTACH_PARENT_PROCESS);
        if (input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE || !GetConsoleMode(input, &previous))
            throw std::runtime_error("请从终端运行此命令，以便安全输入凭证库密码");
        if (!SetConsoleCtrlHandler(interrupt, TRUE)) throw std::runtime_error("无法设置密码输入取消处理");
        handler = true;
    }
    ~Terminal() {
        if (changed) SetConsoleMode(input, previous);
        // ReadConsole can abort before the asynchronous Ctrl+C handler runs. Keep it
        // installed while this CLI error unwinds to exit; removing it early can
        // invoke the default process terminator.
        if (handler && std::uncaught_exceptions() == exceptions) SetConsoleCtrlHandler(interrupt, FALSE);
        if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
        if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    }
    void readOne(const wchar_t *prompt, std::wstring &out) {
        if (!SetConsoleMode(input, (previous | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~ENABLE_ECHO_INPUT))
            throw std::runtime_error("无法关闭终端密码回显");
        changed = true; DWORD count = 0;
        if (!WriteConsoleW(output, prompt, static_cast<DWORD>(wcslen(prompt)), &count, nullptr))
            throw std::runtime_error("无法显示密码提示");
        struct Buffer { wchar_t data[516]{}; ~Buffer() { secureZero(data, sizeof(data)); } } buffer;
        if (!ReadConsoleW(input, buffer.data, 515, &count, nullptr) || !count) {
            FlushConsoleInputBuffer(input);
            throw std::runtime_error("密码输入已取消");
        }
        DWORD written = 0; WriteConsoleW(output, L"\r\n", 2, &written, nullptr);
        if (count >= 515 || buffer.data[count - 1] != L'\n') {
            // Never leave the remainder of a pasted secret for the shell to execute.
            FlushConsoleInputBuffer(input);
            throw std::runtime_error("凭证库密码过长或输入不完整");
        }
        while (count && (buffer.data[count - 1] == L'\r' || buffer.data[count - 1] == L'\n')) --count;
        out.assign(buffer.data, count);
    }
};
#else
volatile std::sig_atomic_t interrupted = 0;
void onInterrupt(int) { interrupted = 1; }
struct Terminal {
    int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    termios previous{}; bool changed = false;
    struct sigaction oldInt{}, oldTerm{}, oldHup{}, oldQuit{};
    Terminal() {
        if (fd < 0 || tcgetattr(fd, &previous) != 0) {
            if (fd >= 0) ::close(fd);
            throw std::runtime_error("请从终端运行此命令，以便安全输入凭证库密码");
        }
        struct sigaction action{}; action.sa_handler = onInterrupt; sigemptyset(&action.sa_mask); // no SA_RESTART
        sigaction(SIGINT, &action, &oldInt); sigaction(SIGTERM, &action, &oldTerm);
        sigaction(SIGHUP, &action, &oldHup); sigaction(SIGQUIT, &action, &oldQuit);
        interrupted = 0;
    }
    ~Terminal() {
        if (changed) tcsetattr(fd, TCSAFLUSH, &previous);
        sigaction(SIGINT, &oldInt, nullptr); sigaction(SIGTERM, &oldTerm, nullptr);
        sigaction(SIGHUP, &oldHup, nullptr); sigaction(SIGQUIT, &oldQuit, nullptr);
        ::close(fd);
    }
    void readOne(const wchar_t *prompt, std::wstring &out) {
        termios quiet = previous; quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO); quiet.c_lflag |= ICANON | ECHONL;
        if (tcsetattr(fd, TCSAFLUSH, &quiet) != 0) throw std::runtime_error("无法关闭终端密码回显");
        changed = true;
        auto text = utf8(prompt); if (::write(fd, text.data(), text.size()) < 0) throw std::runtime_error("无法显示密码提示");
        struct Buffer { char data[2048]{}; ~Buffer() { secureZero(data, sizeof(data)); } } buffer;
        size_t count = 0;
        for (;;) {
            if (interrupted) { tcflush(fd, TCIFLUSH); throw std::runtime_error("密码输入已取消"); }
            auto n = ::read(fd, buffer.data + count, sizeof(buffer.data) - count);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("密码输入已取消");
            count += static_cast<size_t>(n);
            if (buffer.data[count - 1] == '\n') break;
            if (count >= sizeof(buffer.data)) { tcflush(fd, TCIFLUSH); throw std::runtime_error("凭证库密码过长或输入不完整"); }
        }
        while (count && (buffer.data[count - 1] == '\r' || buffer.data[count - 1] == '\n')) --count;
        std::string line(buffer.data, count);
        try { out = widen(line); } catch (...) { wipe(line); throw std::runtime_error("凭证库密码不是有效的 UTF-8 文本"); }
        wipe(line);
    }
};
#endif
std::filesystem::path pathArg(const std::string &value) { return std::filesystem::u8path(value); }
}

void ConsolePassword::read(bool confirm, const wchar_t *prompt) {
    Terminal terminal;
    terminal.readOne(prompt ? prompt : confirm ? L"设置凭证库备份密码（12–256 个字符）：" : L"输入凭证库备份密码：", value);
    if (confirm) {
        std::wstring repeat; struct Clear { std::wstring &s; ~Clear() { wipe(s); } } clear{repeat};
        terminal.readOne(L"再次输入密码：", repeat);
        if (repeat != value) throw std::runtime_error("两次密码不一致；操作已取消");
    }
}
void ConsolePassword::readCode() {
    std::wstring typed; struct Clear { std::wstring &s; ~Clear() { wipe(s); } } clear{typed};
    Terminal().readOne(L"输入云端凭证库恢复码：", typed);
    value = relay::backup::recoveryCode(typed);
}
void ConsolePassword::newCode() {
    value = relay::backup::newRecoveryCode();
    std::printf("Cloud vault recovery code (write it down and keep it offline; it cannot be recovered):\n\n    %s\n\n",
        utf8(relay::backup::displayRecoveryCode(value)).c_str());
    std::fflush(stdout);
    std::wstring typed; struct Clear { std::wstring &s; ~Clear() { wipe(s); } } clear{typed};
    Terminal().readOne(L"再次输入恢复码以确认：", typed);
    if (relay::backup::recoveryCode(typed) != value) throw std::runtime_error("恢复码不一致；操作已取消");
}
relay::Vault &openStorage(relay::Storage &storage) {
    ConsolePassword password;
    if (storage.choice().kind == relay::StorageKind::Cloud) password.readCode();
    return storage.open(password.value);
}
uint16_t parsePort(const std::string &number) {
    if (number.empty() || number.size() > 5 || number.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("端口必须为 1–65535");
    auto value = std::stoul(number); if (!value || value > 65535) throw std::runtime_error("端口必须为 1–65535");
    return static_cast<uint16_t>(value);
}
// Splits "--device SERIAL" out of the arguments. Returns false on misuse.
bool splitDevice(std::vector<std::string> &args, std::string &serial) {
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] != "--device") continue;
        if (!serial.empty() || i + 1 >= args.size() || !validDeviceSerial(args[i + 1])) return false;
        serial = args[i + 1]; args.erase(args.begin() + static_cast<std::ptrdiff_t>(i), args.begin() + static_cast<std::ptrdiff_t>(i) + 2); --i;
    }
    return true;
}
std::vector<std::string> commandLine(int argc, char **argv) {
    std::vector<std::string> args;
#ifdef _WIN32
    (void)argc; (void)argv;
    int count = 0; auto wideArgs = CommandLineToArgvW(GetCommandLineW(), &count);
    for (int i = 1; wideArgs && i < count; ++i) args.push_back(utf8(wideArgs[i]));
    LocalFree(wideArgs);
#else
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
#endif
    return args;
}
bool isGuiCommand(const std::vector<std::string> &args) {
    return args.empty() || (args.size() == 1 && (args[0] == "--accounts" || args[0] == "--safe-end")) ||
        (args[0] == "--serve" && (args.size() == 1 || args.size() == 3));
}
int runCli(const std::vector<std::string> &args, const std::string &selectedSerial) {
    const auto &cmd = args.at(0); auto argc = args.size();
    if (cmd == "--relay-revoke" && argc == 2) {
        forgetRelayDevice(args[1]);
        std::puts("Device public key removed; this safe end now refuses the device. Accounts and other devices are unchanged."); return 0;
    }
    if (cmd == "--relay-enrollments" && argc == 1) {
        for (const auto &serial : relayTrustedDevices()) {
            auto id = hash(relayDeviceKey(serial)); std::printf("%s %s\n", serial.c_str(), hex(id.data(), 16).c_str());
        }
        return 0;
    }
    if (cmd == "--self-test" && argc == 1) {
        selfTest();
        std::puts("PASS: P-256 key roundtrip and signing, public key validation, SHA-256 vector, OS data protection");
        return 0;
    }
    if (cmd == "--generate" && argc == 1) {
        auto k = Key::load();
        if (!k) { k = Key::generate(); k->save(); }
        auto id = k->id(); std::printf("Local key: %s\n", hex(id.data(), 16).c_str());
        return 0;
    }
    if (cmd == "--list-devices" && argc == 1) {
        for (const auto &serial : Device::enumerate()) std::printf("%s\t%s\n", serial.c_str(), utf8(loadDeviceName(serial)).c_str());
        return 0;
    }
    if (cmd == "--vault-init" && argc == 1) {
        relay::Storage storage; storage.initializeLocal();
        std::puts("Local safe-end vault initialized. Network service is not started."); return 0;
    }
    if (cmd == "--vault-export" && argc == 2) {
        relay::Storage storage; auto &vault = openStorage(storage); ConsolePassword password; password.read(true);
        vault.exportBackup(pathArg(args[1]), password.value);
        std::puts("Encrypted vault backup created. Keep its password separately; this is an offline recovery snapshot."); return 0;
    }
    if (cmd == "--vault-import" && argc == 2) {
        ConsolePassword password; password.read(false);
        if (!std::filesystem::is_regular_file(pathArg(args[1]))) throw std::runtime_error("备份文件不存在");
        relay::Storage storage; storage.restoreLocal(pathArg(args[1]), password.value);
        std::puts("Vault restored for this user; credentials, counters and PIN retries preserved. Network service was not started."); return 0;
    }
    if (cmd == "--vault-list" && argc == 1) {
        relay::Storage storage; auto &vault = openStorage(storage);
        for (const auto &a : vault.accounts()) {
            auto label = [](const std::string &s) { return utf8(ctap::Value::string(s).label()); };
            std::printf("%s\t%s\t%s\n", label(a.rp).c_str(), label(a.userName).c_str(), label(a.displayName).c_str());
        }
        return 0;
    }
    if (cmd == "--vault-query" && argc == 3) {
        relay::Storage storage; auto &vault = openStorage(storage);
        bool found = vault.contains(args[1], args[2]); std::puts(found ? "yes" : "no"); return found ? 0 : 2;
    }
    if (cmd == "--vault-reset-pin" && argc == 2) {
        relay::Storage storage; auto &vault = openStorage(storage);
        std::puts(vault.resetDevicePin(args[1]) ? "Device relay PIN cleared; credentials preserved. Set a new PIN before requiring UV." : "This device has no relay PIN.");
        return 0;
    }
    if (cmd == "--storage-new-id" && argc == 1) { auto id = randomBytes(16); std::printf("%s\n", hex(id.data(), id.size()).c_str()); return 0; }
    if (cmd == "--storage-status" && argc == 1) {
        relay::Storage storage; auto choice = storage.choice();
        if (choice.kind == relay::StorageKind::Local) {
            auto marker = relay::Vault::defaultPath(); marker += ".lock";
            auto name = std::filesystem::exists(marker) ? storage.localNamespace() : std::string("uninitialized");
            std::printf("local\t%s\n", name.c_str());
        } else std::printf("%s\t%s\n", choice.kind == relay::StorageKind::Cloud ? "cloud" :
            choice.kind == relay::StorageKind::Unbound ? "unbound" : choice.kind == relay::StorageKind::DetachingCloud ? "pending-detach" :
            choice.kind == relay::StorageKind::MovingToCloud ? "pending-migration" : "pending-initialization", choice.nameSpace.c_str());
        return 0;
    }
    if ((cmd == "--storage-init-cloud" || cmd == "--storage-open-cloud") && argc == 2) {
        const auto &name = args[1]; (void)relay::CloudStorage::identity(name);
        bool create = cmd == "--storage-init-cloud";
        relay::Storage storage; ConsolePassword password;
        if (create) password.newCode(); else password.readCode();
        if (create) storage.initializeCloud(name, password.value); else storage.selectCloud(name, password.value);
        std::puts("Cloud vault selected and verified. Network service is not started."); return 0;
    }
    if (cmd == "--storage-migrate-cloud" && argc == 1) {
        relay::Storage storage; ConsolePassword password;
        std::printf("Migrating local vault %s; its existing cloud profile must use this namespace.\n", storage.localNamespace().c_str());
        std::fflush(stdout);
        password.newCode(); storage.migrateCloud(password.value);
        std::puts("Cloud migration committed. The retained local file is retired and cannot serve credentials."); return 0;
    }
    if (cmd == "--storage-resume" && argc == 1) {
        relay::Storage storage; ConsolePassword password; password.readCode();
        storage.resume(password.value); std::puts("Pending cloud operation completed and selected. Network service is not started."); return 0;
    }
    if (cmd == "--download-ports" && argc == 1) {
        for (const auto &p : esp::downloadPorts()) std::printf("%s\n", p.path.c_str());
        return 0;
    }
    // Erases the whole chip; the GUI asks for confirmation, scripts are trusted.
    if (cmd == "--flash-esp32s3" && (argc == 2 || argc == 3)) {
        auto image = esp::readImage(std::filesystem::u8path(args[1]));
        std::string port = argc == 3 ? args[2] : std::string();
        if (port.empty()) {
            auto ports = esp::downloadPorts();
            if (ports.size() != 1) throw std::runtime_error(ports.empty() ? "未发现下载模式的 ESP32-S3：请按住 BOOT 插入 USB" : "发现多个下载模式设备，请指定串口");
            port = ports[0].path;
        }
        auto link = esp::openSerial(port);
        esp::Progress progress;
        std::exception_ptr error;
        std::atomic_bool finished{false};
        std::thread worker([&] {
            try { esp::flash(*link, image, progress); } catch (...) { error = std::current_exception(); }
            finished = true;
        });
        static const char *stages[] = {"", "connecting", "erasing", "writing", "verifying", "resetting", "done"};
        for (int shown = -1; !finished; sleepMs(200)) {
            int now = progress.stage * 1000 + progress.permille;
            if (now == shown) continue;
            std::printf("\r%-10s %3d%%", stages[progress.stage], progress.permille / 10); std::fflush(stdout); shown = now;
        }
        worker.join();
        if (error) std::rethrow_exception(error);
        std::puts("\nFlashed, verified and reset."); return 0;
    }
    Device d(selectedSerial);
    if (cmd == "--device-reboot" && argc == 1) {
        auto key = Key::load(); if (!key) throw std::runtime_error("请先生成本机密钥并与设备配对");
        RelayControl(d).reboot(*key); std::puts("Device accepted authenticated restart; USB will reconnect. Saved settings apply on startup."); return 0;
    }
#ifdef ENABLE_RELAY_DIAGNOSTICS
    if (cmd == "--device-diagnostics" && argc == 1) {
        std::puts(RelayControl(d).diagnostics().c_str()); return 0;
    }
#endif
    if (cmd == "--relay-query" && argc == 3) {
        auto state = RelayControl(d).status();
        if (state.runningMode != RELAY_MODE_RELAY || (state.flags & 2)) throw std::runtime_error("精确查询需要处于正常中转模式的设备");
        std::atomic_bool cancel{false};
        bool found = queryRelayAccount(d.serial, args[1], args[2], cancel);
        std::puts(found ? "yes" : "no"); return found ? 0 : 2;
    }
    if (cmd == "--relay-status" && argc == 1) {
        auto s = RelayControl(d).status();
        std::printf("Relay config v1; running mode %u profiles %u; stored mode %u profiles %u; flags %u; setup phase %u result %u\n",
            s.runningMode, s.runningNetworks, s.storedMode, s.storedNetworks, s.flags, s.phase, s.result);
        if (s.network) {
            static const char *phases[] = {"idle", "Wi-Fi init", "Wi-Fi connect", "IP address", "DNS/TCP", "reserved", "TLS", "send request", "wait response", "response received"};
            std::printf("Network: phase %u (%s); profile %u; Wi-Fi reason %u; ready %u associated %u IPv4 %u IPv6 %u\n",
                s.networkPhase, s.networkPhase < std::size(phases) ? phases[s.networkPhase] : "unknown", s.networkProfile,
                s.wifiReason, !!(s.networkFlags & 1), !!(s.networkFlags & 2), !!(s.networkFlags & 4), !!(s.networkFlags & 8));
        }
        return 0;
    }
    if (cmd == "--rename" && argc == 2) { saveDeviceName(d.serial, widen(args[1])); std::puts("Device name saved locally."); return 0; }
    if (cmd == "--status" && argc == 1) {
        auto ps = d.pairStatus(); auto st = d.status();
        std::printf("Protocol v2; serial %s; storage %u; paired %u/%u; pair phase %u result %u; pending %u\n",
            d.serial.c_str(), ps.storage, ps.count, ps.capacity, ps.phase, ps.result, st.pending);
        for (auto id : ps.ids)
            if (id != Id{}) std::printf("Trusted: %s\n", hex(id.data(), 16).c_str());
        return 0;
    }
    auto k = Key::load();
    if (!k) throw std::runtime_error("请先生成本机密钥");
    if (cmd == "--pair" && argc == 1) {
        auto tx = d.pair(*k);
        std::puts("Pairing armed. Release BOOT, hold BOOT for 1 second, then release."); std::fflush(stdout);
        for (int i = 0; i < 650; i++) {
            auto ps = d.pairStatus();
            if (ps.tx != tx) throw std::runtime_error("Pair transaction changed");
            if (ps.phase == 7) {
                auto pub = d.publicKey(); trustRelayDevice(d.serial, pub); auto id = hash(pub);
                std::printf("PASS: physical pairing saved; device key %s\n", hex(id.data(), 16).c_str()); return 0;
            }
            if (ps.phase >= 8) throw std::runtime_error("Pairing failed/canceled/expired");
            sleepMs(200);
        }
        throw std::runtime_error("Pairing timed out");
    }
    if (cmd == "--approve" && argc == 3 && args[1] == "--rp") {
        for (int i = 0; i < 300; i++) {
            auto r = d.snapshot();
            if (r.pending) {
                if (r.rp != args[2]) throw std::runtime_error("网站与指定 RP 不一致");
                d.approve(r, *k); std::puts("PASS: one request approved"); return 0;
            }
            sleepMs(100);
        }
        throw std::runtime_error("No matching request");
    }
    throw std::runtime_error("Unknown command");
}
