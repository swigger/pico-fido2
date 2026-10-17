#include "main_window.h"
#include "approval.h"
#include "device_names.h"
#include "device_settings_panel.h"
#include "flash_dialog.h"
#include "relay_settings.h"
#include "safe_end_panel.h"
#include "session_monitor.h"
#include "widgets.h"
#include <QCloseEvent>
#include <QComboBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
const QString lockedText = QStringLiteral("列表已锁定。输入此安全密钥的 FIDO PIN 后读取。");
QLabel *wrapped(const QString &text, QWidget *parent) {
    auto *label = new QLabel(text, parent); label->setWordWrap(true); label->setTextFormat(Qt::PlainText); return label;
}
}
MainWindow::AccountJob::~AccountJob() {
    wipe(pin);
    for (auto &a : result.accounts) { wipe(a.website); wipe(a.account); wipe(a.displayName); wipe(a.userId); }
}

MainWindow::MainWindow(int initialTab, const std::string &serial) : selectedSerial(serial) {
    setWindowTitle(platform::fidoAccessRequiresElevation() && platform::isElevated()
        ? QStringLiteral("ESP32 安全密钥 · 管理（管理员）") : QStringLiteral("ESP32 安全密钥 · 管理"));
    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);
    auto *deviceRow = new QHBoxLayout();
    deviceSelector = new QComboBox(central); deviceSelector->setMinimumWidth(360);
    renameButton = new QPushButton(QStringLiteral("命名设备"), central);
    flashButton = new QPushButton(QStringLiteral("刷写新设备"), central);
    flashButton->setStyleSheet(QStringLiteral("QPushButton { background: #642998; color: white; border: none; border-radius: 4px; padding: 4px 14px; }"
                                              "QPushButton:disabled { background: palette(button); color: palette(mid); }"));
    deviceRow->addWidget(deviceSelector, 1); deviceRow->addWidget(renameButton); deviceRow->addWidget(flashButton);
    layout->addLayout(deviceRow);
    statusText = new QLabel(QStringLiteral("正在连接设备…"), this);
    // One line keeps the layout still; the full text stays in the tooltip.
    statusText->setTextFormat(Qt::PlainText); statusText->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusBar()->addWidget(statusText, 1);
    statusBar()->setSizeGripEnabled(false);

    tabs = new QTabWidget(central);
    auto *devicePage = new QWidget(tabs), *accountsPage = new QWidget(tabs);
    buildDeviceTab(devicePage); buildAccountsTab(accountsPage);
    safeEnd = new SafeEndPanel(tabs);
    tabs->addTab(devicePage, QStringLiteral("授权与设置"));
    tabs->addTab(accountsPage, QStringLiteral("独立模式查询"));
    tabs->addTab(safeEnd, QStringLiteral("中转模式服务"));
    layout->addWidget(tabs, 1);
    setCentralWidget(central);

    connect(renameButton, &QPushButton::clicked, this, &MainWindow::renameDevice);
    connect(flashButton, &QPushButton::clicked, this, &MainWindow::flashNewDevice);
    connect(deviceSelector, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
        if (!idle() || index < 0 || static_cast<size_t>(index) >= availableDevices.size()) { scanDevices(true); return; }
        lockAccounts();
        selectedSerial = availableDevices[static_cast<size_t>(index)];
        device.reset(); request = {}; pairState = {};
        poll();
    });
    // The service tab shows the safe end's own state; the others show the device.
    connect(tabs, &QTabWidget::currentChanged, this, [this](int index) {
        lockAccounts();
        setStatus(index == ServiceTab ? safeEnd->lastMessage() : connection);
        refresh();
    });
    connect(safeEnd, &SafeEndPanel::message, this, [this](const QString &text) { if (tabs->currentIndex() == ServiceTab) setStatus(text); });
    connect(settings, &DeviceSettingsPanel::message, this, &MainWindow::setStatus);
    connect(&SessionMonitor::instance(), &SessionMonitor::locked, this, [this] { lockAccounts(); refresh(); });

    try {
        key = Key::load();
        setStatus(key ? QStringLiteral("请选择网页中的 USB 安全密钥；每台电脑各自生成本机密钥并按 BOOT 配对。")
                      : QStringLiteral("首次使用：生成本机密钥，然后点击“配对”并按 BOOT。"));
    } catch (const std::exception &e) { setStatus(safeLabel(e.what())); }
    tabs->setCurrentIndex(std::clamp(initialTab, 0, 2));
    timer = new QTimer(this); connect(timer, &QTimer::timeout, this, &MainWindow::poll); timer->start(1000); // each poll is a USB round trip to the device
    poll();
    resize(860, 720);
}
MainWindow::~MainWindow() {
    delete popup.data();
    lockAccounts();
    if (accountThread.joinable()) accountThread.join();
}
void MainWindow::buildDeviceTab(QWidget *page) {
    auto *layout = new QVBoxLayout(page);
    auto *keyBox = new QGroupBox(QStringLiteral("本机授权密钥"), page);
    auto *keyLayout = new QVBoxLayout(keyBox);
    auto *keyRow = new QHBoxLayout();
    keyLabel = new QLabel(QStringLiteral("尚未生成本机密钥"), keyBox);
    keyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QFont mono(QStringLiteral("monospace")); mono.setStyleHint(QFont::Monospace); keyLabel->setFont(mono);
    generateButton = new QPushButton(QStringLiteral("生成本机密钥"), keyBox);
    pairButton = new QPushButton(QStringLiteral("配对"), keyBox);
    pairButton->setStyleSheet(QStringLiteral("QPushButton { background: #1f9a1f; color: white; border: none; border-radius: 4px; padding: 4px 18px; }"
                                             "QPushButton:disabled { background: palette(button); color: palette(mid); }"));
    keyRow->addWidget(keyLabel); keyRow->addSpacing(16); keyRow->addWidget(generateButton); keyRow->addWidget(pairButton);
    keyRow->addStretch(1);
    keyLayout->addLayout(keyRow);
    keyLayout->addWidget(new QLabel(QStringLiteral("设备中已授权的公钥"), keyBox));
    auto *trustRow = new QHBoxLayout();
    trusted = new QListWidget(keyBox); trusted->setFont(mono);
    revokeButton = new QPushButton(QStringLiteral("移除所选授权"), keyBox);
    auto *trustButtons = new QVBoxLayout();
    trustButtons->addWidget(revokeButton); trustButtons->addStretch(1);
    trustRow->addWidget(trusted, 1); trustRow->addLayout(trustButtons);
    keyLayout->addLayout(trustRow);
    layout->addWidget(keyBox, 1);

    auto *settingsBox = new QGroupBox(QStringLiteral("设备设置"), page);
    auto *settingsLayout = new QVBoxLayout(settingsBox);
    settings = new DeviceSettingsPanel(settingsBox);
    settingsLayout->addWidget(settings);
    layout->addWidget(settingsBox, 1);

    connect(generateButton, &QPushButton::clicked, this, &MainWindow::generateKey);
    connect(pairButton, &QPushButton::clicked, this, &MainWindow::pairOrCancel);
    connect(revokeButton, &QPushButton::clicked, this, &MainWindow::revokeOrCancel);
}
void MainWindow::buildAccountsTab(QWidget *page) {
    auto *layout = new QVBoxLayout(page);
    layout->addWidget(new QLabel(QStringLiteral("独立工作模式的设备中保存的网站与账号"), page));
    accountHint = wrapped(QString(), page);
    layout->addWidget(accountHint);
    auto *buttons = new QHBoxLayout();
    unlockButton = new QPushButton(page); lockButton = new QPushButton(QStringLiteral("锁定列表"), page);
    buttons->addWidget(unlockButton); buttons->addWidget(lockButton); buttons->addStretch(1);
    layout->addLayout(buttons);
    accountTable = new QTableWidget(0, 4, page);
    accountTable->setHorizontalHeaderLabels({QStringLiteral("网站"), QStringLiteral("账号"), QStringLiteral("显示名称"), QStringLiteral("用户 ID")});
    accountTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    accountTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    accountTable->horizontalHeader()->setStretchLastSection(true);
    accountTable->verticalHeader()->hide();
    layout->addWidget(accountTable, 1);
    layout->addWidget(wrapped(QStringLiteral("只列出密钥内存储的通行密钥。账号名由网站提供；未提供名称时，可用用户 ID 区分。\n"
        "列表仅在本窗口显示 · 切换页签、最小化、锁屏、拔出设备或 5 分钟后自动锁定"), page));
    connect(unlockButton, &QPushButton::clicked, this, &MainWindow::unlockAccounts);
    connect(lockButton, &QPushButton::clicked, this, [this] { lockAccounts(); refresh(); });
}
bool MainWindow::idle() const {
    return !modal && !ownPair && !pairState.active() && !accountJob && !request.pending && !settings->awaiting();
}
// Unknown (older firmware, no device) counts as standalone.
bool MainWindow::relayMode() const {
    const auto &state = settings->deviceState();
    return device && state && state->runningMode == RELAY_MODE_RELAY;
}
// Paired, and no other device operation in progress.
bool MainWindow::settingsUsable() const {
    return device && key && pairState.contains(key->id()) &&
        !(modal || ownPair || pairState.active() || accountJob || request.pending);
}
void MainWindow::setStatus(const QString &text) { if (statusText) { statusText->setText(text); statusText->setToolTip(text); } }
// Connection state is repeated on every poll; only a change replaces newer messages.
void MainWindow::setConnection(const QString &text) {
    if (text == connection) return;
    connection = text;
    if (tabs->currentIndex() != ServiceTab) setStatus(text);
}
void MainWindow::lockAccounts(const QString &message) {
    bool shown = accountsUnlocked || accountJob;
    if (accountJob) accountJob->cancel = true;
    if (accountTable) accountTable->setRowCount(0);
    accountsUnlocked = false; accountsSerial.clear(); accountsExpire = 0;
    if (!message.isEmpty()) setStatus(message);
    else if (shown) setStatus(QStringLiteral("账号列表已锁定。"));
}
void MainWindow::refresh() {
    bool busy = modal || ownPair || pairState.active() || accountJob || request.pending;
    bool writing = settings->awaiting();
    settings->sync(device.get(), key.get(), settingsUsable());
    deviceSelector->setEnabled(idle());
    renameButton->setEnabled(device && !modal && !ownPair && !accountJob);
    flashButton->setEnabled(!modal && !ownPair && !writing);
    generateButton->setEnabled(!ownPair && !writing);
    // Buttons that start a BOOT-confirmed write also cancel it.
    bool pairing = ownPair && ownPairAdds, revoking = ownPair && !ownPairAdds;
    pairButton->setText(pairing ? QStringLiteral("取消配对") : QStringLiteral("配对"));
    pairButton->setEnabled(pairing || (device && key && !busy && !writing));
    revokeButton->setText(revoking ? QStringLiteral("取消移除") : QStringLiteral("移除所选授权"));
    revokeButton->setEnabled(revoking || (device && pairState.count && !busy && !writing));
    bool elevate = platform::fidoAccessRequiresElevation() && !platform::isElevated();
    bool relay = relayMode();
    accountHint->setText(relay ? QStringLiteral("此设备工作于中转模式，账号保存在安全端，请在“中转模式服务”中查看。") :
        elevate ? QStringLiteral("Windows 读取安全密钥需要管理员权限，点击下方按钮后继续。")
                : QStringLiteral("使用与 iPhone / 电脑验证时相同的 FIDO PIN 解锁。") + (accountsUnlocked ? QString() : QStringLiteral("\n") + lockedText));
    unlockButton->setText(elevate ? QStringLiteral("以管理员身份打开账号列表") : accountJob ? QStringLiteral("正在读取…") :
        accountsUnlocked ? QStringLiteral("重新验证并刷新") : QStringLiteral("输入 FIDO PIN 并读取"));
    unlockButton->setEnabled(!accountJob && device && !relay && !busy && !writing);
    lockButton->setEnabled(accountJob || accountsUnlocked);
    keyLabel->setText(key ? hexFingerprint(key->id().data()) : QStringLiteral("尚未生成本机密钥"));
    std::array<Id, 4> next{}; int count = 0;
    for (auto id : pairState.ids)
        if (std::any_of(id.begin(), id.end(), [](auto v) { return v != 0; })) next[static_cast<size_t>(count++)] = id;
    if (next != listIds || count != listCount) {
        listIds = next; listCount = count; trusted->clear();
        for (int i = 0; i < count; ++i) {
            auto text = hexFingerprint(next[static_cast<size_t>(i)].data());
            if (key && next[static_cast<size_t>(i)] == key->id()) text += QStringLiteral("  本机");
            trusted->addItem(text);
        }
        if (count) trusted->setCurrentRow(0);
    }
}
void MainWindow::scanDevices(bool force) {
    if (!force && tickMs() < nextDeviceScan) return;
    nextDeviceScan = tickMs() + 3000;
    auto next = Device::enumerate();
    if (!force && next == availableDevices) return;
    availableDevices = std::move(next);
    // A disconnected selection stays selected by identity. Never silently switch
    // approval or account listing to a different device after unplugging a key.
    if (selectedSerial.empty() && availableDevices.size() == 1) selectedSerial = availableDevices.front();
    deviceSelector->clear();
    for (size_t i = 0; i < availableDevices.size(); ++i) {
        std::wstring name;
        try { name = loadDeviceName(availableDevices[i]); } catch (const std::exception &e) { setStatus(safeLabel(e.what())); }
        deviceSelector->addItem((name.empty() ? QStringLiteral("未命名安全密钥") : qs(name)) + QStringLiteral("  ·  ") + qs(availableDevices[i]));
        if (availableDevices[i] == selectedSerial) deviceSelector->setCurrentIndex(static_cast<int>(i));
    }
    if (std::find(availableDevices.begin(), availableDevices.end(), selectedSerial) == availableDevices.end()) deviceSelector->setCurrentIndex(-1);
}
void MainWindow::poll() {
    if (modal) return;
    try {
        scanDevices();
        if (!device) {
            if (selectedSerial.empty())
                throw std::runtime_error(availableDevices.empty() ? "请连接 ESP32 安全密钥" : "请在上方选择安全密钥");
            device = std::make_unique<Device>(selectedSerial);
        }
        pairState = device->pairStatus();
        request = device->snapshot();
        // Same value refresh() passes: toggling enabled closes the mode popup and drops clicks.
        settings->sync(device.get(), key.get(), settingsUsable());
        settings->poll();
        bool paired = key && pairState.contains(key->id());
        // Firmware or trust files from before device keys: the pairing is only one-way.
        bool known = paired && !relayDeviceKey(device->serial).empty();
        QString status = known ? QStringLiteral("设备已连接 · 本机已授权") :
            paired ? QStringLiteral("设备已连接 · 本机已授权 · 未记下设备公钥，请重新配对")
                   : QStringLiteral("设备已连接 · 本机尚未配对");
        if (!pairState.storage) status = QStringLiteral("设备授权存储不可用");
        if (const auto &s = settings->deviceState()) {
            status += s->runningMode == RELAY_MODE_RELAY ? QStringLiteral(" · 中转模式") : QStringLiteral(" · 独立工作模式");
            if (!(s->flags & RELAY_HID_STORAGE_READY)) status += QStringLiteral(" · 配置存储不可用");
            if (s->flags & RELAY_HID_BOOT_FAULT) status += QStringLiteral(" · 配置异常，凭证操作已停止");
            if (s->flags & RELAY_HID_REBOOT_REQUIRED) status += QStringLiteral(" · 已保存的设置待重启生效");
        }
        setConnection(status);
        if (ownPair) {
            if (pairState.tx != transaction) { ownPair = false; setStatus(QStringLiteral("配对请求已改变，请重新操作。")); }
            else if (pairState.phase == 7) {
                ownPair = false;
                if (ownPairAdds) {
                    // The BOOT press approved this exchange: keep the device's public key for relay trust.
                    trustRelayDevice(device->serial, device->publicKey());
                    setStatus(QStringLiteral("配对完成：设备已授权本机公钥，本机已记下设备公钥。拔插设备后仍然有效。"));
                } else setStatus(QStringLiteral("授权列表已保存。"));
            }
            else if (pairState.phase >= 8) {
                ownPair = false;
                setStatus(QStringLiteral("未完成（状态 %1）。请重新发起，期间不要进行网页登录。").arg(pairState.result));
            } else if (pairState.phase == 5) setStatus(QStringLiteral("已检测到长按，请松开 BOOT，设备随后会保存授权。"));
        }
    } catch (const std::exception &e) {
        if (accountsUnlocked || accountJob) lockAccounts(QStringLiteral("设备已断开，列表已锁定。请连接设备后重新解锁。"));
        device.reset(); request = {}; pairState = {}; ownPair = false;
        settings->sync(nullptr, nullptr, false);
        setConnection(safeLabel(e.what()));
    }
    if (accountsUnlocked && (!device || device->serial != accountsSerial || tickMs() >= accountsExpire))
        lockAccounts(QStringLiteral("列表已自动锁定，请重新输入 FIDO PIN。"));
    if (accountJob && accountJob->done) finishAccounts();
    updatePopup();
    refresh();
}
// A web request waiting on a standalone device opens the shared approval
// dialog; it closes as soon as the device stops waiting (BOOT, timeout, unplug).
void MainWindow::updatePopup() {
    bool paired = device && key && pairState.contains(key->id());
    if (popup && !(paired && request.same(popupRequest))) { popup->done(QDialog::Rejected); popup.clear(); }
    if (popup || modal || ownPair || !paired || !request.pending || request.same(dismissed)) return;
    relay::Approval approval;
    approval.operation = request.operation; approval.rp = request.rp; approval.deviceSerial = device->serial;
    popupRequest = request;
    auto *dialog = new ApprovalDialog(approval, std::chrono::steady_clock::now() + std::chrono::milliseconds(request.remaining), true);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    connect(dialog, &QDialog::finished, this, [this](int result) {
        auto shown = popupRequest; dismissed = shown; popup.clear();
        if (result == QDialog::Accepted) QMetaObject::invokeMethod(this, [this, shown] { approve(shown); }, Qt::QueuedConnection);
    });
    popup = dialog;
    dialog->present();
}
void MainWindow::run(const std::function<void()> &action, const QString &title) {
    if (modal) return;
    modal = true;
    try { action(); } catch (const std::exception &e) { setStatus(safeLabel(e.what())); showError(this, title, e); }
    modal = false;
    poll();
}
void MainWindow::approve(const Request &shown) {
    run([this, shown] {
        if (!device || !key || !request.same(shown)) { setStatus(QStringLiteral("该网页请求已结束。")); return; }
        device->approve(shown, *key);
        setStatus(QStringLiteral("本次请求已确认，请返回网页。"));
        request = {};
    });
}
void MainWindow::generateKey() {
    run([this] {
        if (key && QMessageBox::question(this, QStringLiteral("生成新密钥"),
                QStringLiteral("生成新密钥后需要重新按 BOOT 配对。旧本机密钥会保留受保护的备份。继续吗？")) != QMessageBox::Yes) return;
        auto fresh = Key::generate(); fresh->save(); key = std::move(fresh); listCount = -1;
        setStatus(QStringLiteral("本机密钥已生成。点击“配对”把公钥写入设备。"));
    });
}
void MainWindow::pairOrCancel() {
    if (ownPair) { if (ownPairAdds) cancelPair(); return; }
    run([this] {
        if (!device || !key) return;
        transaction = device->pair(*key); ownPair = ownPairAdds = true;
        setStatus(QStringLiteral("设备蓝灯闪烁：请先松开 BOOT，再按住约 1 秒后松开，批准本机公钥。再次点击可取消。"));
    });
}
void MainWindow::revokeOrCancel() {
    if (ownPair) { if (!ownPairAdds) cancelPair(); return; }
    run([this] {
        int row = trusted->currentRow();
        if (!device || row < 0 || row >= listCount) return;
        transaction = device->revoke(listIds[static_cast<size_t>(row)]); ownPair = true; ownPairAdds = false;
        setStatus(QStringLiteral("移除所选授权：设备蓝灯闪烁，请先松开 BOOT，再按住约 1 秒后松开。再次点击可取消。"));
    });
}
void MainWindow::cancelPair() {
    run([this] {
        if (!device || !ownPair) return;
        device->cancel(transaction); ownPair = false;
        setStatus(QStringLiteral("已取消，授权列表未改变。"));
    });
}
void MainWindow::renameDevice() {
    if (!device || ownPair || accountJob) return;
    run([this] {
        auto name = loadDeviceName(device->serial);
        for (;;) {
            if (!askText(this, QStringLiteral("命名设备"), QStringLiteral("设备名称"), name, false, false, 0, 32,
                    QStringLiteral("最多 32 个 UTF-8 字节；留空恢复未命名。名称仅保存在本机控制软件中。"))) return;
            try { validateDeviceName(name); break; }
            catch (const std::exception &e) { showError(this, QStringLiteral("检查设备名称"), e); }
        }
        saveDeviceName(device->serial, name);
        setStatus(QStringLiteral("设备名称已保存，仅在本机控制软件中显示。"));
        scanDevices(true);
    });
}
// The chip in download mode is not a FIDO device, so this never touches the selected one.
void MainWindow::flashNewDevice() {
    run([this] {
        FlashDialog dialog(this);
        dialog.exec();
        scanDevices(true);
    }, QStringLiteral("刷写新设备"));
}
void MainWindow::unlockAccounts() {
    if (modal || accountJob || !device || ownPair || pairState.active() || request.pending || relayMode()) return;
#ifdef _WIN32
    if (platform::fidoAccessRequiresElevation() && !platform::isElevated()) {
        auto path = platform::executablePath();
        auto args = L"--accounts --device " + widen(device->serial);
        auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(reinterpret_cast<HWND>(winId()), L"runas", path.c_str(), args.c_str(), nullptr, SW_SHOWNORMAL));
        setStatus(result <= 32 ? QStringLiteral("未打开管理员窗口，请允许 Windows 权限提示后重试。")
                               : QStringLiteral("请在新打开的管理员窗口中输入 FIDO PIN。"));
        return;
    }
#endif
    lockAccounts();
    auto job = std::make_shared<AccountJob>();
    job->serial = device->serial;
    modal = true;
    bool entered = askText(this, QStringLiteral("独立模式查询"), QStringLiteral("输入此安全密钥的 FIDO PIN"), job->pin, true, false, 1, 63);
    modal = false;
    if (!entered) { refresh(); return; }
    setStatus(QStringLiteral("正在验证 PIN 并读取账号，请保持设备连接…"));
    if (accountThread.joinable()) accountThread.join();
    accountJob = job;
    accountThread = std::thread([this, job] {
        try { job->result = readAccounts(job->serial, job->pin, job->cancel); }
        catch (const std::exception &e) { try { job->error = widen(e.what()); } catch (...) { job->error = L"读取失败"; } }
        wipe(job->pin);
        job->done = true;
        QMetaObject::invokeMethod(this, [this] { finishAccounts(); refresh(); }, Qt::QueuedConnection);
    });
    refresh();
}
void MainWindow::finishAccounts() {
    if (!accountJob || !accountJob->done) return;
    if (accountThread.joinable()) accountThread.join();
    auto job = std::move(accountJob);
    if (job->cancel || tabs->currentIndex() != AccountsTab || isMinimized() || !device || device->serial != job->serial) return;
    if (!job->error.empty()) { setStatus(qs(job->error)); return; }
    accountTable->setRowCount(0);
    for (const auto &a : job->result.accounts) {
        int row = accountTable->rowCount(); accountTable->insertRow(row);
        accountTable->setItem(row, 0, new QTableWidgetItem(qs(a.website)));
        accountTable->setItem(row, 1, new QTableWidgetItem(a.account.empty() ? QStringLiteral("（网站未提供）") : qs(a.account)));
        accountTable->setItem(row, 2, new QTableWidgetItem(qs(a.displayName)));
        accountTable->setItem(row, 3, new QTableWidgetItem(qs(a.userId)));
    }
    accountTable->resizeColumnsToContents();
    accountsUnlocked = true; accountsSerial = job->serial; accountsExpire = tickMs() + 5 * 60 * 1000;
    setStatus(job->result.accounts.empty() ? QStringLiteral("PIN 验证成功。密钥中没有可列出的通行密钥。") :
        QStringLiteral("PIN 验证成功 · %1 个网站 · %2 条账号记录").arg(job->result.websites).arg(job->result.accounts.size()));
}
void MainWindow::changeEvent(QEvent *event) {
    if (event->type() == QEvent::WindowStateChange && isMinimized()) { lockAccounts(); refresh(); }
    QMainWindow::changeEvent(event);
}
void MainWindow::closeEvent(QCloseEvent *event) {
    if (ownPair && device) { try { device->cancel(transaction); } catch (...) {} }
    settings->cancel();
    if (popup) popup->done(QDialog::Rejected);
    safeEnd->shutdown();
    lockAccounts();
    timer->stop();
    event->accept();
}
