"""Exercise backup password input in an isolated Windows pseudoconsole.

Only imports a guaranteed nonexistent temporary path. Uses fictional passwords,
never creates a vault, never touches USB and never controls the user's terminal.
"""
import ctypes as C
from ctypes import wintypes as W
import sys
import tempfile
import time
import subprocess
from pathlib import Path


K = C.WinDLL("kernel32", use_last_error=True)
H = W.HANDLE


class Coord(C.Structure):
    _fields_ = [("X", C.c_short), ("Y", C.c_short)]


class Startup(C.Structure):
    _fields_ = [("cb", W.DWORD), ("reserved", W.LPWSTR), ("desktop", W.LPWSTR), ("title", W.LPWSTR),
        ("x", W.DWORD), ("y", W.DWORD), ("width", W.DWORD), ("height", W.DWORD),
        ("charsX", W.DWORD), ("charsY", W.DWORD), ("fill", W.DWORD), ("flags", W.DWORD),
        ("show", W.WORD), ("reservedCount", W.WORD), ("reservedBytes", C.POINTER(C.c_byte)),
        ("input", H), ("output", H), ("error", H)]


class StartupEx(C.Structure):
    _fields_ = [("base", Startup), ("attributes", C.c_void_p)]


class Process(C.Structure):
    _fields_ = [("process", H), ("thread", H), ("pid", W.DWORD), ("tid", W.DWORD)]


def api(name, result, *args):
    f = getattr(K, name); f.restype, f.argtypes = result, args
    return f


pipe = api("CreatePipe", W.BOOL, C.POINTER(H), C.POINTER(H), C.c_void_p, W.DWORD)
close = api("CloseHandle", W.BOOL, H)
pseudo = api("CreatePseudoConsole", C.c_long, Coord, H, H, W.DWORD, C.POINTER(H))
close_pseudo = api("ClosePseudoConsole", None, H)
init_attrs = api("InitializeProcThreadAttributeList", W.BOOL, C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t))
set_attr = api("UpdateProcThreadAttribute", W.BOOL, C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p)
delete_attrs = api("DeleteProcThreadAttributeList", None, C.c_void_p)
create = api("CreateProcessW", W.BOOL, W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD,
    C.c_void_p, W.LPCWSTR, C.POINTER(StartupEx), C.POINTER(Process))
read = api("ReadFile", W.BOOL, H, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
write = api("WriteFile", W.BOOL, H, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
peek = api("PeekNamedPipe", W.BOOL, H, C.c_void_p, W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.c_void_p)
wait = api("WaitForSingleObject", W.DWORD, H, W.DWORD)
exit_code = api("GetExitCodeProcess", W.BOOL, H, C.POINTER(W.DWORD))
terminate = api("TerminateProcess", W.BOOL, H, W.UINT)


def check(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


def scenario(executable, host, missing, response):
    incoming, sender, receiver, outgoing, console = H(), H(), H(), H(), H()
    process, attrs, captured = Process(), None, bytearray()
    try:
        check(pipe(C.byref(incoming), C.byref(sender), None, 0))
        check(pipe(C.byref(receiver), C.byref(outgoing), None, 0))
        check(pseudo(Coord(120, 30), incoming, outgoing, 0, C.byref(console)) >= 0)
        size = C.c_size_t()
        init_attrs(None, 1, 0, C.byref(size))
        attrs = C.create_string_buffer(size.value)
        check(init_attrs(attrs, 1, 0, C.byref(size)))
        check(set_attr(attrs, 0, 0x00020016, console, C.sizeof(H), None, None))
        startup = StartupEx(); startup.base.cb = C.sizeof(startup); startup.attributes = C.cast(attrs, C.c_void_p)
        # The console host handles its own broadcast Ctrl+C without swallowing
        # the child's event. cmd.exe can exit first and mask the actual result.
        command = C.create_unicode_buffer(subprocess.list2cmdline([str(host), "--console-host", str(executable), str(missing)]))
        check(create(str(host), command, None, None, False, 0x00080000, None, None, C.byref(startup), C.byref(process)))
        sent, deadline = False, time.monotonic() + 10
        while time.monotonic() < deadline:
            available = W.DWORD()
            if peek(receiver, None, 0, None, C.byref(available), None) and available.value:
                buffer = C.create_string_buffer(available.value); count = W.DWORD()
                check(read(receiver, buffer, available.value, C.byref(count), None))
                captured.extend(buffer.raw[:count.value])
            if not sent and "输入凭证库备份密码：".encode() in captured:
                count = W.DWORD(); check(write(sender, response, len(response), C.byref(count), None)); sent = True
            if wait(process.process, 0) == 0:
                code = W.DWORD(); check(exit_code(process.process, C.byref(code)))
                assert sent and code.value == 1, (code.value, captured.decode(errors="replace"))
                assert b"fictional-backup-secret" not in captured, "password echoed"
                return
            time.sleep(0.02)
        raise AssertionError("private password console timed out: " + captured.decode(errors="replace"))
    finally:
        if process.process and wait(process.process, 0) != 0:
            terminate(process.process, 99)  # Only the disposable child created above.
            wait(process.process, 3000)
        if attrs is not None:
            delete_attrs(attrs)
        if console:
            close_pseudo(console)
        for handle in (process.thread, process.process, incoming, sender, receiver, outgoing):
            if handle:
                close(handle)


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve(strict=True)
    host = Path(sys.argv[2]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="pf2-console-test-") as directory:
        missing = Path(directory) / "does-not-exist.pf2bak"
        for response in (b"fictional-backup-secret\r", b"\x03", b"fictional-backup-secret" + b"x" * 600 + b"\r"):
            scenario(executable, host, missing, response)
        assert list(Path(directory).iterdir()) == []
    print("PASS: isolated terminal password no-echo, Ctrl+C cancellation and oversized-input rejection")
