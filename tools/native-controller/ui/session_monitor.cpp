#include "session_monitor.h"
#ifdef _WIN32
#include <windows.h>
#include <wtsapi32.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#endif
#ifdef PICO_SESSION_DBUS
#include <QDBusConnection>
#endif

struct SessionMonitor::Impl {
#ifdef _WIN32
    HWND window = nullptr;
    static LRESULT CALLBACK procedure(HWND w, UINT message, WPARAM wp, LPARAM lp) {
        if (message == WM_WTSSESSION_CHANGE && (wp == WTS_SESSION_LOCK || wp == WTS_SESSION_LOGOFF ||
            wp == WTS_CONSOLE_DISCONNECT || wp == WTS_REMOTE_DISCONNECT))
            emit SessionMonitor::instance().locked();
        return DefWindowProcW(w, message, wp, lp);
    }
    Impl() {
        WNDCLASSW cls{}; cls.lpfnWndProc = procedure; cls.hInstance = GetModuleHandleW(nullptr);
        cls.lpszClassName = L"PicoFidoSessionMonitor"; RegisterClassW(&cls);
        window = CreateWindowExW(0, cls.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, cls.hInstance, nullptr);
        if (window) WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION);
    }
    ~Impl() { if (window) { WTSUnRegisterSessionNotification(window); DestroyWindow(window); } }
#elif defined(__APPLE__)
    static void callback(CFNotificationCenterRef, void *, CFNotificationName, const void *, CFDictionaryRef) {
        emit SessionMonitor::instance().locked();
    }
    Impl() {
        CFNotificationCenterAddObserver(CFNotificationCenterGetDistributedCenter(), this, callback,
            CFSTR("com.apple.screenIsLocked"), nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
    }
    ~Impl() { CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDistributedCenter(), this); }
#endif
};
SessionMonitor &SessionMonitor::instance() { static SessionMonitor monitor; return monitor; }
SessionMonitor::SessionMonitor() : impl(std::make_unique<Impl>()) {
#ifdef PICO_SESSION_DBUS
    // Best effort: desktops without these signals report no lock. Extra matches
    // (another session) only cause an unnecessary lock.
    auto session = QDBusConnection::sessionBus();
    // freedesktop (KDE and others, two object paths in use) and GNOME screensavers.
    for (const auto &path : {QStringLiteral("/org/freedesktop/ScreenSaver"), QStringLiteral("/ScreenSaver")})
        session.connect(QString(), path, QStringLiteral("org.freedesktop.ScreenSaver"), QStringLiteral("ActiveChanged"), this, SLOT(screensaverActive(bool)));
    session.connect(QString(), QStringLiteral("/org/gnome/ScreenSaver"), QStringLiteral("org.gnome.ScreenSaver"),
        QStringLiteral("ActiveChanged"), this, SLOT(screensaverActive(bool)));
    QDBusConnection::systemBus().connect(QStringLiteral("org.freedesktop.login1"), QString(),
        QStringLiteral("org.freedesktop.login1.Session"), QStringLiteral("Lock"), this, SLOT(sessionLock()));
#endif
}
SessionMonitor::~SessionMonitor() = default;
#ifdef PICO_SESSION_DBUS
void SessionMonitor::screensaverActive(bool active) { if (active) emit locked(); }
void SessionMonitor::sessionLock() { emit locked(); }
#endif
