#pragma once
#include "safe_end_session.h"
#include <QWidget>
#include <map>
#include <memory>

class QLabel;
class QPushButton;
class QTableWidget;

// The "中转模式服务" tab: safe-end vault management (open/lock, local
// initialization and encrypted backup, cloud profiles and migration, device
// revocation) and the relay service with per-request approval. Once the service
// has been started it starts again with the next launch until it is stopped by
// hand. Locking the desktop does not stop it; failures are retried until manual
// stop/exit. All storage work runs on the SafeEndSession worker; this panel only
// submits jobs and renders snapshots. Status text goes to the main status bar.
class SafeEndPanel : public QWidget {
    Q_OBJECT
public:
    using ServiceRunner = std::function<void(relay::SafeEndSession &, const std::string &, uint16_t,
        relay::Authenticator::Approve, const std::function<void(uint16_t)> &)>;
    explicit SafeEndPanel(QWidget *parent = nullptr, const std::filesystem::path &directory = {}, ServiceRunner runner = {});
    ~SafeEndPanel() override;
    // Cancels any job, stops the service and releases the vault (window close).
    void shutdown();
    const QString &lastMessage() const { return last; }
signals:
    void message(const QString &text);
private:
    enum Action { Open, Lock, Refresh, Initialize, Restore, Backup, ResetPin, Profile, NewCloud, ExistingCloud, Migrate, Resume,
                  Serve, RevokeDevice };
    std::unique_ptr<relay::SafeEndSession> session;
    ServiceRunner runService;
    std::map<Action, QPushButton *> buttons;
    QLabel *nameSpace = nullptr;
    QTableWidget *table = nullptr;
    QString last;
    uint64_t shown = UINT64_MAX, epoch = 0;
    bool redact = false, shownBusy = false, shownRedact = false, answering = false, closing = false;
    bool serving = false, autoChecked = false;
    void changed();
    void showState();
    void handleQuestion();
    void command(Action action);
    void serve();
    void startService(const QString &address, uint16_t port);
    void cloudAction(Action action);
    void profileAction();
    void revokeDevice();
    void lock();
};
