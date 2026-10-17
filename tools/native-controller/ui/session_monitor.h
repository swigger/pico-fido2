#pragma once
#include <QObject>
#include <memory>

// Emits locked() when the desktop session locks, logs off or disconnects, so
// windows can hide accounts and cancel approvals. Windows: WTS notifications;
// macOS: the distributed "screen is locked" notification; Linux: logind/
// screensaver D-Bus signals when Qt DBus is available.
class SessionMonitor : public QObject {
    Q_OBJECT
public:
    static SessionMonitor &instance();
    ~SessionMonitor() override;
signals:
    void locked();
private:
    SessionMonitor();
    struct Impl;
    std::unique_ptr<Impl> impl;
    friend struct Impl;
#ifdef PICO_SESSION_DBUS
private slots:
    void screensaverActive(bool active);
    void sessionLock();
#endif
};
