#pragma once
#include "core.h"
#include "credentials.h"
#include <QMainWindow>
#include <QPointer>
#include <atomic>
#include <memory>
#include <thread>

class ApprovalDialog;
class DeviceSettingsPanel;
class QComboBox;
class QLabel;
class QListWidget;
class QPushButton;
class SafeEndPanel;
class QTabWidget;
class QTableWidget;
class QTimer;

// Local controller: device selection and naming; controller key, BOOT pairing
// and device settings; the PIN-gated list of passkeys stored on a standalone
// device; and the relay (safe-end) service. A pending web request on a
// standalone device opens the shared approval dialog. One status bar shows the
// latest message.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    enum Tab { DeviceTab, AccountsTab, ServiceTab };
    explicit MainWindow(int initialTab, const std::string &selectedSerial);
    ~MainWindow() override;
protected:
    void closeEvent(QCloseEvent *event) override;
    void changeEvent(QEvent *event) override;
private:
    struct AccountJob {
        std::atomic_bool cancel{false}, done{false};
        std::wstring pin, error;
        std::string serial;
        AccountSnapshot result;
        ~AccountJob();
    };
    std::unique_ptr<Key> key;
    std::unique_ptr<Device> device;
    Request request, popupRequest, dismissed;
    PairStatus pairState;
    Id transaction{};
    bool ownPair = false, ownPairAdds = false, modal = false, accountsUnlocked = false;
    std::vector<std::string> availableDevices;
    std::string selectedSerial, accountsSerial;
    uint64_t nextDeviceScan = 0, accountsExpire = 0;
    std::array<Id, 4> listIds{};
    int listCount = -1;
    std::shared_ptr<AccountJob> accountJob;
    std::thread accountThread;
    QString connection;

    QTabWidget *tabs = nullptr;
    QComboBox *deviceSelector = nullptr;
    QPushButton *renameButton = nullptr, *flashButton = nullptr;
    QLabel *statusText = nullptr, *keyLabel = nullptr;
    QPushButton *generateButton = nullptr, *pairButton = nullptr, *revokeButton = nullptr;
    QListWidget *trusted = nullptr;
    DeviceSettingsPanel *settings = nullptr;
    QLabel *accountHint = nullptr;
    QPushButton *unlockButton = nullptr;
    QTableWidget *accountTable = nullptr;
    SafeEndPanel *safeEnd = nullptr;
    QPointer<ApprovalDialog> popup;
    QTimer *timer = nullptr;

    void buildDeviceTab(QWidget *page);
    void buildAccountsTab(QWidget *page);
    void poll();
    void refresh();
    void scanDevices(bool force = false);
    void setStatus(const QString &text);
    void setConnection(const QString &text);
    void updatePopup();
    void lockAccounts(const QString &message = {});
    void finishAccounts();
    void unlockAccounts();
    void run(const std::function<void()> &action, const QString &title = QStringLiteral("操作未完成"));
    void approve(const Request &request);
    void generateKey();
    void pairOrCancel();
    void revokeOrCancel();
    void cancelPair();
    void renameDevice();
    void flashNewDevice();
    bool relayMode() const;
    bool settingsUsable() const;
    bool idle() const;
};
