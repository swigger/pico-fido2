#include "foreground.h"
#include <QWidget>

void activateForApproval(QWidget *window) {
    window->raise();
    window->activateWindow();
}

#ifdef _WIN32
#include <windows.h>

intptr_t otherForeground() {
    HWND window = GetForegroundWindow(); DWORD pid = 0;
    if (!window || !GetWindowThreadProcessId(window, &pid) || pid == GetCurrentProcessId()) return 0;
    return reinterpret_cast<intptr_t>(window);
}
void restoreForeground(intptr_t previous) {
    auto window = reinterpret_cast<HWND>(previous); DWORD pid = 0;
    HWND front = GetForegroundWindow();
    if (!window || !IsWindow(window) || !front || !GetWindowThreadProcessId(front, &pid) || pid != GetCurrentProcessId()) return;
    SetForegroundWindow(window); // allowed: this process owns the foreground
}
#else
// Window managers decide focus on other platforms.
intptr_t otherForeground() { return 0; }
void restoreForeground(intptr_t) {}
#endif
