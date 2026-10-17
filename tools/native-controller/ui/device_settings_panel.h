#pragma once
#include "relay_control.h"
#include "relay_settings.h"
#include <QWidget>
#include <optional>

class QComboBox;
class QCheckBox;
class QListWidget;
class QPushButton;

// The "设备设置" group of the main window: work mode and up to ten Wi-Fi +
// safe-end profiles. The draft is protected per device on this computer and
// saved after every edit. 写入设备 signs it with the paired controller key,
// uploads it over USB and waits for the BOOT press; while waiting the same
// button cancels. Progress and results go to the main window's status bar.
class DeviceSettingsPanel : public QWidget {
    Q_OBJECT
public:
    explicit DeviceSettingsPanel(QWidget *parent);
    ~DeviceSettingsPanel() override;
    // The current device (may be null) and whether the controller is paired with
    // no other device operation in progress. No device I/O.
    void sync(Device *device, const Key *key, bool usable);
    // Called on every main-window poll: reads the device state and finishes a write.
    void poll();
    bool awaiting() const { return waiting; }
    // Last device-reported relay state; empty for unsupported firmware or no device.
    const std::optional<RelayStatus> &deviceState() const { return state; }
    void cancel(); // aborts a pending write (window close)
signals:
    void message(const QString &text);
private:
    Device *device = nullptr;
    const Key *key = nullptr;
    std::string serial;
    relay_config_t draft{};
    std::optional<RelayStatus> state;
    RelayTicket ticket;
    bool waiting = false, usable = false;
    int ticks = 0;
    QString lastNetwork;
    QComboBox *mode = nullptr;
    QListWidget *profiles = nullptr;
    QPushButton *read = nullptr, *write = nullptr, *add = nullptr, *edit = nullptr, *remove = nullptr;
    QPushButton *restartButton = nullptr;
    QCheckBox *autoRestart = nullptr;
    void restartDevice();
    void load(const std::string &serial);
    void list(int row);
    void refresh();
    void editNetwork(int index);
    void removeNetwork();
    void persist();
    void readDevice();
    void writeOrCancel();
    void stage();
    void check();
};
