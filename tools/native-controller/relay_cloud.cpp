#include "relay_cloud.h"
#include "relay_backup.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace relay {
namespace {
constexpr size_t maxPayload = backup::maxPlaintext + backup::overhead + 9;
void need(bool ok) { if (!ok) throw std::runtime_error("云端凭证库不可用，已停止当前会话；不会回退到本机库"); }
void put(Bytes &b, size_t at, uint64_t n, unsigned width) {
    for (unsigned i = 0; i < width; ++i) b[at + i] = static_cast<uint8_t>(n >> (i * 8));
}
uint64_t get(const Bytes &b, size_t at, unsigned width) {
    need(at <= b.size() && width <= b.size() - at); uint64_t n = 0;
    for (unsigned i = 0; i < width; ++i) n |= uint64_t(b[at + i]) << (i * 8);
    return n;
}
using Live = std::function<void()>;
std::filesystem::path defaultHelper() {
#ifdef _WIN32
    return platform::executablePath().parent_path() / "PicoFidoStorage.exe";
#else
    return platform::executablePath().parent_path() / "PicoFidoStorage";
#endif
}
#ifdef _WIN32
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
    ~Handle() { reset(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    void reset(HANDLE value = INVALID_HANDLE_VALUE) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = value;
    }
};
std::wstring quote(const std::wstring &arg) {
    need(arg.find(L'\0') == std::wstring::npos); std::wstring out = L"\""; size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        out.append(slashes * (c == L'\"' ? 2 : 1), L'\\'); slashes = 0;
        if (c == L'\"') out += L'\\';
        out += c;
    }
    out.append(slashes * 2, L'\\'); return out + L'\"';
}
struct PipeSecurity {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PipeSecurity() {
        Handle token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h)); DWORD size = 0;
        GetTokenInformation(token.h, TokenUser, nullptr, 0, &size); need(size > 0);
        Bytes data(size); need(GetTokenInformation(token.h, TokenUser, data.data(), size, &size));
        LPWSTR sid = nullptr; need(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &sid));
        struct Free { LPWSTR p; ~Free() { LocalFree(p); } } cleanup{sid};
        auto dacl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(sid) + L")";
        need(ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &descriptor, nullptr));
    }
    ~PipeSecurity() { if (descriptor) LocalFree(descriptor); }
};
void makePipe(Handle &parent, Handle &child, bool parentWrites) {
    auto nonce = randomBytes(24); auto name = L"\\\\.\\pipe\\PicoFidoStorage-" + widen(hex(nonce.data(), nonce.size()));
    PipeSecurity security; SECURITY_ATTRIBUTES attr{sizeof(attr), security.descriptor, FALSE};
    parent.reset(CreateNamedPipeW(name.c_str(), (parentWrites ? PIPE_ACCESS_OUTBOUND : PIPE_ACCESS_INBOUND) |
        FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attr));
    need(parent.h != INVALID_HANDLE_VALUE); attr.bInheritHandle = TRUE;
    child.reset(CreateFileW(name.c_str(), parentWrites ? GENERIC_READ : GENERIC_WRITE, 0, &attr, OPEN_EXISTING, 0, nullptr));
    need(child.h != INVALID_HANDLE_VALUE);
    // The parent connects both ends before launching; no pipe names go to the child.
    OVERLAPPED ov{}; Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr)); need(event.h != nullptr); ov.hEvent = event.h;
    need(ConnectNamedPipe(parent.h, &ov) || GetLastError() == ERROR_PIPE_CONNECTED);
}
struct Attributes {
    Bytes buffer; LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    Attributes() {
        SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 2, 0, &size); need(size > 0); buffer.resize(size);
        list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
        if (!InitializeProcThreadAttributeList(list, 2, 0, &size)) { list = nullptr; need(false); }
    }
    ~Attributes() { if (list) DeleteProcThreadAttributeList(list); }
};
// One helper process with private inherited pipes inside a kill-on-close job.
struct Child {
    Handle input, output, process, job;
    Child(const std::filesystem::path &helper, const std::vector<std::string> &args) {
        Handle childIn, childOut; makePipe(input, childIn, true); makePipe(output, childOut, false);
        SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
        Handle errors(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
        need(errors.h != INVALID_HANDLE_VALUE); job.reset(CreateJobObjectW(nullptr, nullptr)); need(job.h != nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        need(SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
        Attributes attributes; HANDLE inherited[]{childIn.h, childOut.h, errors.h};
        need(UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr));
        // Atomic job assignment also closes the parent-crash window during spawn.
        need(UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job.h, sizeof(job.h), nullptr, nullptr));
        STARTUPINFOEXW start{}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = attributes.list;
        start.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        start.StartupInfo.hStdInput = childIn.h; start.StartupInfo.hStdOutput = childOut.h; start.StartupInfo.hStdError = errors.h;
        auto command = quote(helper.wstring());
        for (const auto &arg : args) command += L" " + quote(widen(arg));
        PROCESS_INFORMATION pi{};
        need(CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, helper.parent_path().c_str(), &start.StartupInfo, &pi));
        process.reset(pi.hProcess); CloseHandle(pi.hThread);
    }
    void io(unsigned char *data, size_t size, bool write, const Live &live) {
        HANDLE pipe = write ? input.h : output.h;
        while (size) {
            live(); Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr)); need(event.h != nullptr);
            OVERLAPPED ov{}; ov.hEvent = event.h; DWORD n = 0; auto chunk = static_cast<DWORD>(std::min<size_t>(size, 65536));
            bool ok = (write ? WriteFile(pipe, data, chunk, &n, &ov) : ReadFile(pipe, data, chunk, &n, &ov)) != FALSE;
            if (!ok) {
                need(GetLastError() == ERROR_IO_PENDING);
                // Cancellation must complete before the stack OVERLAPPED/buffer dies.
                struct Pending {
                    HANDLE pipe; OVERLAPPED *ov; bool active = true;
                    ~Pending() { if (active) { CancelIoEx(pipe, ov); DWORD ignored = 0; GetOverlappedResult(pipe, ov, &ignored, TRUE); } }
                } pending{pipe, &ov};
                for (;;) {
                    auto status = WaitForSingleObject(event.h, 25); live();
                    if (status == WAIT_OBJECT_0) break;
                    need(status == WAIT_TIMEOUT);
                }
                ok = GetOverlappedResult(pipe, &ov, &n, FALSE) != FALSE; pending.active = false;
            }
            need(ok && n && n <= chunk); data += n; size -= n;
        }
    }
    void closePipes() noexcept { input.reset(); output.reset(); }
    int exitCode(unsigned waitMs) noexcept {
        if (WaitForSingleObject(process.h, waitMs) != WAIT_OBJECT_0) return -1;
        DWORD code = 0; return GetExitCodeProcess(process.h, &code) ? static_cast<int>(code) : -1;
    }
    // Pipes closed: the helper exits on EOF. The job kills anything left over.
    void finish() noexcept {
        closePipes();
        if (process.h != INVALID_HANDLE_VALUE) WaitForSingleObject(process.h, 1000);
        job.reset();
    }
    void kill() noexcept { closePipes(); job.reset(); }
};
#else
struct Fd {
    int fd = -1;
    Fd() = default;
    ~Fd() { reset(); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    void reset(int value = -1) noexcept { if (fd >= 0) ::close(fd); fd = value; }
};
void makePipe(Fd &read, Fd &write) {
    int fds[2];
#ifdef __APPLE__
    need(::pipe(fds) == 0);
    for (int f : fds) need(::fcntl(f, F_SETFD, FD_CLOEXEC) == 0);
#else
    need(::pipe2(fds, O_CLOEXEC) == 0);
#endif
    read.reset(fds[0]); write.reset(fds[1]);
}
// One helper process in its own process group, with anonymous pipes on fd 0/1.
// Every other descriptor is closed in the child; the group is killed on teardown.
struct Child {
    Fd input, output;
    pid_t pid = -1, group = -1;
    int result = -1;
    Child(const std::filesystem::path &helper, const std::vector<std::string> &args) {
        static std::once_flag once;
        std::call_once(once, [] { std::signal(SIGPIPE, SIG_IGN); }); // EPIPE instead of process termination
        Fd childIn, childOut; makePipe(childIn, input); makePipe(output, childOut);
        for (int f : {input.fd, output.fd}) need(::fcntl(f, F_SETFL, ::fcntl(f, F_GETFL) | O_NONBLOCK) == 0);
        posix_spawn_file_actions_t actions; need(posix_spawn_file_actions_init(&actions) == 0);
        posix_spawnattr_t attributes;
        if (posix_spawnattr_init(&attributes) != 0) { posix_spawn_file_actions_destroy(&actions); need(false); }
        struct Free {
            posix_spawn_file_actions_t &a; posix_spawnattr_t &b;
            ~Free() { posix_spawn_file_actions_destroy(&a); posix_spawnattr_destroy(&b); }
        } free{actions, attributes};
        short flags = POSIX_SPAWN_SETPGROUP;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
        flags |= POSIX_SPAWN_CLOEXEC_DEFAULT; // macOS: only the dup2 targets survive exec
#endif
        need(posix_spawnattr_setflags(&attributes, flags) == 0 && posix_spawnattr_setpgroup(&attributes, 0) == 0);
        need(posix_spawn_file_actions_adddup2(&actions, childIn.fd, 0) == 0 &&
            posix_spawn_file_actions_adddup2(&actions, childOut.fd, 1) == 0 &&
            posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) == 0);
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
        need(posix_spawn_file_actions_addclosefrom_np(&actions, 3) == 0);
#endif
        auto file = helper.string(); auto directory = helper.parent_path().string();
#if defined(__APPLE__)
        // The portable name exists only from macOS 26; the _np form works from 10.15.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        need(posix_spawn_file_actions_addchdir_np(&actions, directory.c_str()) == 0);
#pragma clang diagnostic pop
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 29))
        need(posix_spawn_file_actions_addchdir_np(&actions, directory.c_str()) == 0);
#endif
        std::vector<std::string> storage{file}; storage.insert(storage.end(), args.begin(), args.end());
        std::vector<char *> argv;
        for (auto &arg : storage) { need(arg.find('\0') == std::string::npos); argv.push_back(arg.data()); }
        argv.push_back(nullptr);
        need(posix_spawn(&pid, file.c_str(), &actions, &attributes, argv.data(), environ) == 0);
        group = pid;
    }
    ~Child() { kill(); }
    void io(unsigned char *data, size_t size, bool write, const Live &live) {
        int fd = write ? input.fd : output.fd; need(fd >= 0);
        while (size) {
            live();
            auto n = write ? ::write(fd, data, std::min<size_t>(size, 65536)) : ::read(fd, data, std::min<size_t>(size, 65536));
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                pollfd p{fd, static_cast<short>(write ? POLLOUT : POLLIN), 0}; ::poll(&p, 1, 25); continue;
            }
            need(n > 0); data += n; size -= static_cast<size_t>(n);
        }
    }
    void closePipes() noexcept { input.reset(); output.reset(); }
    bool reap(unsigned waitMs) noexcept {
        for (unsigned i = 0; pid > 0; ++i) {
            int status = 0; auto r = ::waitpid(pid, &status, WNOHANG);
            if (r == pid || (r < 0 && errno != EINTR)) {
                if (r == pid && WIFEXITED(status)) result = WEXITSTATUS(status);
                pid = -1; break;
            }
            if (i * 10 >= waitMs) return false;
            sleepMs(10);
        }
        return true;
    }
    int exitCode(unsigned waitMs) noexcept { return reap(waitMs) ? result : -1; }
    void finish() noexcept { closePipes(); if (!reap(1000)) kill(); killGroup(); }
    // Like the Windows kill-on-close job: nothing the helper started outlives it.
    void killGroup() noexcept { if (group > 0) { ::kill(-group, SIGKILL); group = -1; } }
    void kill() noexcept {
        closePipes();
        if (pid > 0) { ::kill(pid, SIGKILL); killGroup(); reap(5000); }
        killGroup();
    }
};
#endif
}
struct CloudStorage::Impl {
    struct IdleExpired {};
    std::unique_ptr<Child> child;
    std::filesystem::path helper;
    std::vector<std::string> args;
    uint64_t sequence = 0;
    bool opened = false, faulted = false, closed = false, retained = false;
    std::chrono::milliseconds timeout;
    std::function<bool()> canceled;
    std::function<bool()> parentCanceled;
    explicit Impl(const std::string &nameSpace, const CloudLaunch &launch, unsigned mode = 0) : timeout(launch.timeout), parentCanceled(launch.canceled) {
        (void)CloudStorage::identity(nameSpace); need(timeout.count() > 0 && timeout <= std::chrono::minutes(6));
        helper = launch.helper.empty() ? defaultHelper() : launch.helper;
        need(helper.is_absolute() && (launch.profile.empty() || launch.profile.is_absolute()));
        std::error_code error;
        if (!std::filesystem::is_regular_file(helper, error))
            throw std::runtime_error("安装包不完整或云存储组件无法访问，请重新安装完整程序");
        need(mode <= 3);
        args = {mode == 3 ? "--maintain-pipe" : mode == 2 ? "--enroll-pipe" : mode == 1 ? "--setup-pipe" : "--pipe", nameSpace};
        if (!launch.profile.empty()) args.push_back(launch.profile.u8string());
        child = std::make_unique<Child>(helper, args);
    }
    void prepare() {
        need(!opened && !faulted && !closed);
        if (retained) {
            try { need(exchange(13, {}).empty()); }
            catch (const IdleExpired &) {
                child = std::make_unique<Child>(helper, args);
                sequence = 0; faulted = false;
            }
            retained = false;
        }
    }
    void stop() noexcept {
        faulted = true; if (child) child->kill();
    }
    void live(std::chrono::steady_clock::time_point deadline) {
        need(!faulted && !closed && std::chrono::steady_clock::now() < deadline && (!canceled || !canceled()) && (!parentCanceled || !parentCanceled()));
    }
    void io(unsigned char *data, size_t size, bool write, std::chrono::steady_clock::time_point deadline) {
        child->io(data, size, write, [&] { live(deadline); });
    }
    Bytes exchange(uint8_t op, const Bytes &body, std::chrono::milliseconds limit = std::chrono::milliseconds(0)) {
        try {
            need(!faulted && !closed && body.size() <= maxPayload && sequence < UINT64_MAX - 1);
            // Large vault transfers get one extra second per 64 KiB (the helper scales likewise).
            auto scaled = timeout + std::chrono::seconds(((op == 1 || op == 11) ? maxPayload : body.size()) / 65536);
            auto deadline = std::chrono::steady_clock::now() + (limit.count() ? limit : std::min<std::chrono::milliseconds>(scaled, std::chrono::minutes(6)));
            Bytes header(24); memcpy(header.data(), "PF2STO01", 8); put(header, 8, body.size(), 4); header[12] = op; put(header, 16, ++sequence, 8);
            io(header.data(), header.size(), true, deadline);
            if (!body.empty()) io(const_cast<unsigned char *>(body.data()), body.size(), true, deadline);
            io(header.data(), header.size(), false, deadline);
            need(!memcmp(header.data(), "PF2STO01", 8) && header[12] == (op | 0x80) &&
                !header[13] && !header[14] && !header[15] && get(header, 16, 8) == sequence);
            auto size = get(header, 8, 4); need(size > 0 && size <= maxPayload);
            Bytes response(static_cast<size_t>(size)); io(response.data(), response.size(), false, deadline);
            if (response.size() == 1 && response[0] == 2) throw CloudIntegrityError{};
            need(response[0] == 0); response.erase(response.begin()); return response;
        } catch (...) {
            // A Wake has no storage effects. Only exit 0 after Release means
            // normal idle expiry; failed/ambiguous writes are never retried.
            int code = op == 13 && retained ? child->exitCode(1000) : -1;
            stop();
            if (code == 0) throw IdleExpired{};
            if (code == 2) throw CloudIntegrityError{};
            throw;
        }
    }
};
Id CloudStorage::identity(const std::string &nameSpace) {
    need(nameSpace.size() == 32); Id id{};
    auto digit = [](char c) -> uint8_t { need((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10); };
    for (size_t i = 0; i < id.size(); ++i) id[i] = static_cast<uint8_t>((digit(nameSpace[i * 2]) << 4) | digit(nameSpace[i * 2 + 1]));
    need(id != Id{}); return id;
}
CloudStorage::CloudStorage(const std::string &nameSpace, const CloudLaunch &launch) : state(std::make_unique<Impl>(nameSpace, launch)) {}
void CloudStorage::forgetProfile(const std::string &nameSpace, const CloudLaunch &launch) {
    (void)identity(nameSpace);
    auto path = launch.profile.empty() ? platform::dataDirectory() / "safe-end" / "cloud" /
        (nameSpace + platform::protectedExtension()) : launch.profile;
    need(path.is_absolute());
    auto marker = path; marker += ".lock";
    // Keep the lock inode: unlinking an OS lock could let two helpers own
    // different inodes for the same profile. CreateProfile can reuse this marker.
    platform::FileLock lock(marker, platform::FileLock::Mode::OpenExisting, "云配置正在使用或锁标记不可用；请关闭其他窗口后重试解除绑定");
    const std::string expected = "PF2CLCK1" + nameSpace;
    need(lock.size() == expected.size());
    auto bytes = lock.read(expected.size()); need(bytes == Bytes(expected.begin(), expected.end()));
    std::error_code error;
    auto status = std::filesystem::symlink_status(path, error);
    if (status.type() == std::filesystem::file_type::not_found && (!error || error == std::errc::no_such_file_or_directory)) return;
    need(!error && std::filesystem::is_regular_file(status));
    platform::removeFileChecked(path, "无法删除本机云授权配置；解除绑定尚未完成，请重试");
}
void CloudStorage::saveProfile(const std::string &nameSpace, const Bytes &setupJson, const CloudLaunch &launch) {
    need(!setupJson.empty() && setupJson.size() <= 256 * 1024);
    Impl setup(nameSpace, launch, true); need(setup.exchange(6, setupJson).empty());
    setup.child->finish();
}
void CloudStorage::enrollProfile(const std::string &nameSpace, const Bytes &setupJson,
                               const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch) {
    profileFlow(nameSpace, setupJson, ask, launch, false);
}
void CloudStorage::updateProfile(const std::string &nameSpace, const Bytes &patchJson,
                               const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch) {
    profileFlow(nameSpace, patchJson, ask, launch, true);
}
void CloudStorage::profileFlow(const std::string &nameSpace, const Bytes &setupJson,
                              const std::function<std::string(const EnrollmentQuestion &)> &ask, const CloudLaunch &launch, bool update) {
    need(!setupJson.empty() && setupJson.size() <= 256 * 1024 && static_cast<bool>(ask));
    Impl setup(nameSpace, launch, update ? 3 : 2); auto response = setup.exchange(update ? 10 : 7, setupJson);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    for (;;) {
        setup.live(deadline); need(!response.empty() && response.size() <= 256 * 1024);
        uint8_t kind = response[0];
        if (kind == 0) { need(response.size() == 1); break; }
        if (kind == 2) { need(response.size() == 1); sleepMs(100); response = setup.exchange(9, {}); continue; }
        need(kind == 1 || kind == 3 || kind == 4);
        EnrollmentQuestion question; question.kind = kind; size_t position = 1;
        auto string = [&] {
            auto length = get(response, position, 4); position += 4;
            need(length <= 8192 && position + length <= response.size());
            std::string value(response.begin() + position, response.begin() + position + static_cast<size_t>(length)); position += static_cast<size_t>(length);
            need(value.find('\0') == std::string::npos && validUtf8(value)); return value;
        };
        if (kind == 1) {
            question.value = string(); bool allowed = false;
            for (const auto *host : {"accounts.google.com", "login.microsoftonline.com", "login.microsoftonline.us", "login.microsoftonline.de", "login.chinacloudapi.cn"})
                if (question.value.rfind(std::string("https://") + host + "/", 0) == 0) allowed = true;
            need(allowed && std::none_of(question.value.begin(), question.value.end(), [](unsigned char c) { return c <= 32 || c == 127; }));
        } else {
            question.name = string(); question.message = string(); question.value = string();
            auto flags = get(response, position++, 1); need(flags <= 7);
            question.required = (flags & 1) != 0; question.exclusive = (flags & 2) != 0; question.secret = (flags & 4) != 0;
            auto count = get(response, position, 2); position += 2; need(count <= 128);
            for (uint64_t i = 0; i < count; ++i) { auto value = string(); auto text = string(); question.choices.emplace_back(std::move(value), std::move(text)); }
            need(!question.exclusive || !question.choices.empty());
            need(kind != 4 || question.name == "save_profile");
        }
        need(position == response.size()); auto answer = ask(question); setup.live(deadline);
        need(answer.size() <= 8192 && answer.find('\0') == std::string::npos && validUtf8(answer));
        if (kind == 1) { need(answer == "opened"); response = setup.exchange(9, {}); }
        else {
            need(!question.required || !answer.empty());
            if (question.exclusive) need(std::any_of(question.choices.begin(), question.choices.end(), [&](const auto &choice) { return choice.first == answer; }));
            Bytes bytes(answer.begin(), answer.end()); secureZero(answer.data(), answer.size());
            struct Clear { Bytes &b; ~Clear() { if (!b.empty()) secureZero(b.data(), b.size()); } } clear{bytes};
            response = setup.exchange(8, bytes);
        }
    }
    setup.child->finish();
}
CloudStorage::~CloudStorage() { try { close(); } catch (...) {} }
CloudSnapshot CloudStorage::open(bool initialize, bool resume, const Bytes &creationToken) {
    try {
        state->prepare();
        need(!state->opened && !(initialize && resume)); state->opened = true;
        need((creationToken.empty() || creationToken.size() == 32) && (!resume || creationToken.size() == 32) && (initialize || resume || creationToken.empty()));
        Bytes body{static_cast<uint8_t>(resume ? 2 : initialize ? 1 : 0)}; body.insert(body.end(), creationToken.begin(), creationToken.end());
        auto response = state->exchange(1, body);
        CloudSnapshot result; result.generation = get(response, 0, 8);
        result.encrypted.assign(response.begin() + 8, response.end());
        bool empty = !result.generation && result.encrypted.empty();
        bool populated = result.generation && result.encrypted.size() >= 112 && !memcmp(result.encrypted.data(), "PF2BAK01", 8);
        need(resume ? (empty || populated) : initialize ? empty : populated);
        return result;
    } catch (...) { state->stop(); throw; }
}
void CloudStorage::check() {
    try { need(state->opened); need(state->exchange(3, {}).empty()); }
    catch (...) { state->stop(); throw; }
}
CloudSnapshot CloudStorage::openCached(uint64_t generation, const Bytes &ciphertextHash) {
    try {
        state->prepare();
        need(!state->opened && generation && ciphertextHash.size() == 32); state->opened = true;
        Bytes body(8); put(body, 0, generation, 8); body.insert(body.end(), ciphertextHash.begin(), ciphertextHash.end());
        auto response = state->exchange(11, body);
        CloudSnapshot result; result.generation = get(response, 0, 8);
        result.encrypted.assign(response.begin() + 8, response.end());
        need(result.encrypted.empty() ? result.generation == generation :
            result.generation && result.encrypted.size() >= 112 && !memcmp(result.encrypted.data(), "PF2BAK01", 8));
        return result;
    } catch (...) { state->stop(); throw; }
}
uint64_t CloudStorage::commit(uint64_t expected, const Bytes &encrypted) {
    try {
        need(state->opened && expected != UINT64_MAX && encrypted.size() >= 112 && encrypted.size() <= maxPayload - 9 &&
            !memcmp(encrypted.data(), "PF2BAK01", 8));
        Bytes body(8); put(body, 0, expected, 8); body.insert(body.end(), encrypted.begin(), encrypted.end());
        auto response = state->exchange(4, body); need(response.size() == 8 && get(response, 0, 8) == expected + 1); return expected + 1;
    } catch (...) { state->stop(); throw; }
}
void CloudStorage::release() {
    need(state && state->opened && !state->faulted && !state->closed);
    // Keep USB progress alive while releasing the lease, even if cancellation
    // arrived after a confirmed commit. Do not retain request-stack callbacks.
    auto progress = state->canceled;
    state->canceled = [progress] { if (progress) (void)progress(); return false; };
    try {
        need(state->exchange(12, {}, std::chrono::seconds(5)).empty());
        state->opened = false; state->retained = true; state->canceled = {};
    } catch (...) { state->canceled = {}; state->stop(); throw; }
}
void CloudStorage::close() {
    if (!state || state->closed) return;
    // Closing a short transaction is still part of the CTAP operation. Poll
    // its progress hook so a slow lease release does not suppress keepalives.
    // Cleanup itself has a bounded grace period even after cancellation.
    auto progress = state->canceled;
    state->canceled = [progress] { if (progress) (void)progress(); return false; };
    state->parentCanceled = {};
    if (state->opened && !state->faulted) {
        try { need(state->exchange(5, {}, std::chrono::seconds(5)).empty()); }
        catch (...) { state->stop(); state->closed = true; throw; }
    }
    state->closed = true;
    // Only this instance's child is waited for and, if needed, killed.
    state->child->finish();
}
void CloudStorage::cancellation(std::function<bool()> canceled) { state->canceled = std::move(canceled); }
}
