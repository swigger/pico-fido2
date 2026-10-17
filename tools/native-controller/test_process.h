#pragma once
// Test-only helpers: raw stdio for pipe fixtures and spawning this executable.
#include "platform.h"
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace test {
// Reads or writes exactly b.size() bytes on stdin/stdout; small write chunks
// exercise the parent's reassembly. Throws on EOF or error.
inline void transfer(Bytes &b, bool writing) {
    size_t pos = 0;
    while (pos < b.size()) {
        size_t count = std::min<size_t>(b.size() - pos, writing ? 7 : 65536);
#ifdef _WIN32
        DWORD n = 0; HANDLE h = GetStdHandle(writing ? STD_OUTPUT_HANDLE : STD_INPUT_HANDLE);
        bool ok = writing ? WriteFile(h, b.data() + pos, static_cast<DWORD>(count), &n, nullptr) : ReadFile(h, b.data() + pos, static_cast<DWORD>(count), &n, nullptr);
        if (!ok || !n) throw std::runtime_error("fixture pipe closed");
#else
        auto n = writing ? ::write(1, b.data() + pos, count) : ::read(0, b.data() + pos, count);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw std::runtime_error("fixture pipe closed");
#endif
        pos += static_cast<size_t>(n);
    }
}
// Runs a program with arguments and returns its exit code, or -1 on timeout (killed).
inline int run(const std::filesystem::path &program, const std::vector<std::string> &args, unsigned timeoutMs) {
#ifdef _WIN32
    auto quote = [](const std::wstring &s) { return L"\"" + s + L"\""; };
    auto command = quote(program.wstring());
    for (const auto &a : args) command += L" " + quote(widen(a));
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
    if (!CreateProcessW(program.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child))
        throw std::runtime_error("cannot start test child");
    CloseHandle(child.hThread);
    auto status = WaitForSingleObject(child.hProcess, timeoutMs); DWORD code = 99;
    if (status == WAIT_TIMEOUT) { TerminateProcess(child.hProcess, 99); WaitForSingleObject(child.hProcess, 3000); CloseHandle(child.hProcess); return -1; }
    GetExitCodeProcess(child.hProcess, &code); CloseHandle(child.hProcess);
    return static_cast<int>(code);
#else
    std::vector<std::string> storage{program.string()}; storage.insert(storage.end(), args.begin(), args.end());
    std::vector<char *> argv; for (auto &a : storage) argv.push_back(a.data()); argv.push_back(nullptr);
    pid_t pid = -1;
    if (posix_spawn(&pid, storage[0].c_str(), nullptr, nullptr, argv.data(), environ) != 0) throw std::runtime_error("cannot start test child");
    for (unsigned waited = 0;; waited += 10) {
        int status = 0; auto r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
        if (waited >= timeoutMs) { ::kill(pid, SIGKILL); ::waitpid(pid, &status, 0); return -1; }
        sleepMs(10);
    }
#endif
}
// While alive, atomic replacement of `path` fails (Windows: a handle without
// delete sharing; elsewhere: the directory is made read-only).
struct BlockReplace {
#ifdef _WIN32
    HANDLE handle;
    explicit BlockReplace(const std::filesystem::path &path)
        : handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)) {
        if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("fault injection handle");
    }
    ~BlockReplace() { CloseHandle(handle); }
#else
    std::filesystem::path directory;
    explicit BlockReplace(const std::filesystem::path &path) : directory(path.parent_path()) {
        if (::chmod(directory.c_str(), 0500) != 0) throw std::runtime_error("fault injection chmod");
    }
    ~BlockReplace() { ::chmod(directory.c_str(), 0700); }
#endif
    BlockReplace(const BlockReplace &) = delete;
    BlockReplace &operator=(const BlockReplace &) = delete;
};
inline std::filesystem::path withSuffix(std::filesystem::path p, const char *suffix) { p += suffix; return p; }
}
