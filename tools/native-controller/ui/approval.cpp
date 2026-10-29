#include "approval.h"
#include "device_names.h"
#include "foreground.h"
#include "relay_transport.h"
#include "session_monitor.h"
#include "widgets.h"
#include <QApplication>
#include <QDialogButtonBox>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <condition_variable>
#include <memory>
#include <mutex>

ApprovalDialog::ApprovalDialog(const relay::Approval &a, std::chrono::steady_clock::time_point until, bool standalone)
    : approval(a), deadline(until), local(standalone) {
    bool query = approval.operation == RELAY_CTAP_EXACT_QUERY, pin = approval.pinSubcommand != 0;
    setWindowTitle(local ? QStringLiteral("独立工作模式 · 确认通行密钥请求") : pin ? QStringLiteral("中转模式 · 确认设备 PIN 请求")
                       : query ? QStringLiteral("中转模式 · 确认账号查询") : QStringLiteral("中转模式 · 确认通行密钥请求"));
    setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
    // Other windows may be running their own modal dialogs; a newer modal
    // dialog is the only one that can still receive input.
    setWindowModality(Qt::ApplicationModal);
    auto *layout = new QVBoxLayout(this);
    std::wstring name;
    try { name = loadDeviceName(approval.deviceSerial); } catch (...) {}
    auto device = name.empty() ? qs(approval.deviceSerial) : qs(name) + QStringLiteral(" · ") + qs(approval.deviceSerial);
    auto add = [&](const QString &text) { auto *l = new QLabel(text, this); l->setWordWrap(true); l->setTextFormat(Qt::PlainText); layout->addWidget(l); return l; };
    add(QStringLiteral("来自设备：") + device);
    auto *site = new QPlainTextEdit(pin && approval.rp.empty() ? QStringLiteral("当前设备") : safeLabel(approval.rp), this);
    site->setReadOnly(true); site->setMaximumHeight(70);
    add(pin ? QStringLiteral("范围：") : QStringLiteral("网站："));
    layout->addWidget(site);
    QString title, details;
    if (pin) {
        auto sub = approval.pinSubcommand;
        title = sub == 3 ? QStringLiteral("为此设备设置用于验证身份的中转 PIN。") : sub == 4 ? QStringLiteral("更改此设备用于验证身份的中转 PIN。")
                         : QStringLiteral("验证设备 PIN。后续登录或注册仍需单独批准。");
        details = sub == 3 || sub == 4 ? QStringLiteral("请确认此请求由你发起。PIN 在目标设备上输入；此窗口不会显示 PIN。") : QStringLiteral("本次允许用途：");
        if (sub == 5 || sub == 9) {
            if (approval.pinPermissions & 1) details += QStringLiteral("注册通行密钥  ");
            if (approval.pinPermissions & 2) details += QStringLiteral("登录");
            if (!approval.pinPermissions) details += QStringLiteral("无");
        }
    }
    if (local) add(approval.operation == 1 ? QStringLiteral("请求创建通行密钥。确认网站后批准，也可以直接在设备上按 BOOT。")
                                           : QStringLiteral("请求登录。确认网站后批准，也可以直接在设备上按 BOOT。"));
    else add(pin ? title : query ? QStringLiteral("请求查询下方完整账号是否存在。批准后仅返回是或否。")
            : approval.batchWindowSeconds ? QStringLiteral("请求检查此网站是否存在匹配的通行密钥。")
            : approval.operation == 1 ? QStringLiteral("请求创建通行密钥。确认网站和账号后批准。") : QStringLiteral("请求登录。请选择本次允许使用的账号。"));
    if (local) {
        // The device does not reveal its local accounts; BOOT or this approval covers the request.
    } else if (pin || query) {
        auto *text = new QPlainTextEdit(pin ? details : safeLabel(approval.queryUserName), this);
        text->setReadOnly(true); layout->addWidget(text);
    } else {
        list = new QListWidget(this);
        for (const auto &account : approval.accounts) {
            auto text = safeLabel(account.userName);
            if (!account.displayName.empty()) text += QStringLiteral("  ·  ") + safeLabel(account.displayName);
            if (text.isEmpty()) text = QStringLiteral("用户 ID：") + qs(hex(account.userId.data(), account.userId.size()));
            list->addItem(text);
        }
        if (approval.accounts.empty()) list->addItem(QStringLiteral("此网站没有可用账号。确认后将返回查询结果。"));
        if (approval.accounts.size() <= 1) list->setCurrentRow(0);
        list->setEnabled(approval.operation == 2 && approval.accounts.size() > 1);
        layout->addWidget(list);
    }
    if (!local && approval.batchWindowSeconds)
        add(QStringLiteral("确认后 %1 秒内，同一操作的后续无匹配账号查询将自动确认。注册或使用已有账号仍需单独批准。")
            .arg(approval.batchWindowSeconds));
    remaining = add(QString());
    auto *buttons = new QDialogButtonBox(this);
    approve = buttons->addButton(!local && !pin && !query && approval.accounts.empty() ? QStringLiteral("确认查询") : QStringLiteral("批准本次请求"), QDialogButtonBox::AcceptRole);
    auto *deny = buttons->addButton(local ? QStringLiteral("关闭") : QStringLiteral("拒绝"), QDialogButtonBox::RejectRole);
    deny->setDefault(true); deny->setFocus();
    approve->setEnabled(local || pin || query || approval.accounts.size() <= 1);
    if (list) connect(list, &QListWidget::currentRowChanged, this, [this](int row) { approve->setEnabled(row >= 0); });
    connect(approve, &QPushButton::clicked, this, &ApprovalDialog::allow);
    connect(deny, &QPushButton::clicked, this, &QDialog::reject);
    layout->addWidget(buttons);
    connect(&SessionMonitor::instance(), &SessionMonitor::locked, this, &QDialog::reject);
    auto *timer = new QTimer(this); connect(timer, &QTimer::timeout, this, &ApprovalDialog::tick); timer->start(100);
    tick();
    resize(640, local ? 300 : 480);
}
void ApprovalDialog::present() {
    auto previous = otherForeground();
    connect(this, &QDialog::finished, qApp, [previous] {
        // After Qt has activated the next window; not while another request still waits.
        QTimer::singleShot(0, qApp, [previous] {
            for (auto *w : QApplication::topLevelWidgets())
                if (qobject_cast<ApprovalDialog *>(w) && w->isVisible()) return;
            restoreForeground(previous);
        });
    });
    show();
    activateForApproval(this);
    // Activation is a request, not a guarantee. Also draw attention to a
    // pending approval if the window manager leaves the browser in front.
    QApplication::alert(this);
}
void ApprovalDialog::tick() {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(deadline - std::chrono::steady_clock::now()).count();
    if (seconds < 0) { reject(); return; }
    remaining->setText(local ? QStringLiteral("剩余 %1 秒 · 关闭后仍可在设备上按 BOOT 批准").arg(seconds)
                            : approval.batchWindowSeconds ? QStringLiteral("剩余 %1 秒 · 等待确认查询").arg(seconds)
                            : QStringLiteral("剩余 %1 秒 · 此批准仅用于当前请求").arg(seconds));
}
void ApprovalDialog::allow() {
    if (std::chrono::steady_clock::now() >= deadline) { reject(); return; }
    if (!local && approval.operation == 2 && !approval.accounts.empty()) {
        int row = list ? list->currentRow() : -1;
        if (row < 0 || static_cast<size_t>(row) >= approval.accounts.size()) return;
        result.credentialId = approval.accounts[static_cast<size_t>(row)].credentialId;
    }
    result.allow = true;
    accept();
}

relay::Decision approveOnGui(const relay::Approval &approval, const relay::Operation &operation) {
    struct Shared {
        std::mutex mutex; std::condition_variable wake;
        bool done = false, close = false; relay::Decision decision;
        QPointer<ApprovalDialog> dialog;
    };
    auto shared = std::make_shared<Shared>();
    auto deadline = operation.deadline;
    QMetaObject::invokeMethod(qApp, [shared, approval, deadline] {
        { std::lock_guard<std::mutex> guard(shared->mutex); if (shared->close) { shared->done = true; shared->wake.notify_all(); return; } }
        auto *dialog = new ApprovalDialog(approval, deadline);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        shared->dialog = dialog;
        QObject::connect(dialog, &QDialog::finished, [shared, dialog](int) {
            std::lock_guard<std::mutex> guard(shared->mutex);
            shared->decision = dialog->decision(); shared->done = true; shared->wake.notify_all();
        });
        dialog->present();
    }, Qt::QueuedConnection);
    std::unique_lock<std::mutex> guard(shared->mutex);
    while (!shared->done) {
        guard.unlock();
        bool stop = (operation.canceled && operation.canceled()) || std::chrono::steady_clock::now() >= deadline;
        guard.lock();
        if (stop) {
            shared->close = true; shared->decision = {};
            QMetaObject::invokeMethod(qApp, [shared] { if (shared->dialog) shared->dialog->reject(); }, Qt::QueuedConnection);
            // Wait briefly so the dialog closes before the next request may open one.
            shared->wake.wait_for(guard, std::chrono::seconds(2), [&] { return shared->done; });
            return {};
        }
        shared->wake.wait_for(guard, std::chrono::milliseconds(100));
    }
    return shared->decision;
}
