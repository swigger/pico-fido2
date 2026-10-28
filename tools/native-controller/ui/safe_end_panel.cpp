#include "safe_end_panel.h"
#include "approval.h"
#include "credentials.h"
#include "device_names.h"
#include "relay_backup.h"
#include "relay_profile.h"
#include "relay_settings.h"
#include "relay_tls.h"
#include "session_monitor.h"
#include "widgets.h"
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QTableWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <algorithm>

using namespace relay;
namespace {
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Secret {
    std::wstring value;
    bool remember = false;
    ~Secret() { wipe(value); }
};
struct ClearFields {
    QVector<FormField> &fields;
    ~ClearFields() { for (auto &field : fields) field.value.fill(QChar(0)); }
};
std::wstring recovery(const QString &value) {
    Secret typed{ws(value)}; return backup::recoveryCode(typed.value);
}
std::shared_ptr<Secret> password(QWidget *parent, const QString &title, bool confirm, const QString &explanation = {}) {
    auto secret = std::make_shared<Secret>();
    auto hint = !explanation.isEmpty() ? explanation : confirm ? QStringLiteral("设置 12–256 个字符的密码，并妥善保存。")
                                                               : QStringLiteral("输入此凭证库的密码。关闭窗口会取消操作。");
    if (!askText(parent, title, QStringLiteral("密码"), secret->value, true, confirm, confirm ? 12 : 1, 256, hint)) return {};
    return secret;
}
// Cloud vaults use a generated recovery code instead of a chosen password, so a
// leaked cloud copy cannot be brute-forced offline.
FormField rememberCode() {
    FormField field; field.title = QStringLiteral("在此电脑上记住恢复码（使用系统安全存储）"); field.checkbox = true;
    return field;
}
std::shared_ptr<Secret> enterCode(QWidget *parent, const QString &title, const QString &explanation = {}) {
    auto secret = std::make_shared<Secret>();
    FormField code; code.title = QStringLiteral("恢复码"); code.secret = true; code.limit = 64;
    QVector<FormField> fields{code, rememberCode()};
    ClearFields clear{fields};
    if (!FormDialog::ask(parent, title, (explanation.isEmpty() ? QString() : explanation + '\n') +
            QStringLiteral("输入建立此云端库时生成的 26 位恢复码；大小写、空格和横线均可。"), fields,
            [](const QVector<QString> &values) {
                try { Secret check{recovery(values[0])}; return QString(); }
                catch (...) { return QStringLiteral("恢复码格式不正确，请输入完整的 26 位恢复码。"); }
            })) return {};
    secret->value = recovery(fields[0].value); secret->remember = fields[1].value == QStringLiteral("1");
    fields[0].value.fill(QChar(0)); return secret;
}
FormField text(const QString &title, const QString &value = {}, int limit = 512, bool required = true, bool readOnly = false) {
    FormField f; f.title = title; f.value = value; f.limit = limit; f.required = required; f.readOnly = readOnly; return f;
}
FormField secretField(const QString &title, int limit = 1024, bool required = true) {
    auto f = text(title, {}, limit, required); f.secret = true; return f;
}
FormField fileField(const QString &title, bool required = true) { auto f = text(title, {}, 32767, required); f.file = true; return f; }
FormField choice(const QString &title, const QString &value, QVector<QPair<QString, QString>> choices, bool editable = false) {
    auto f = text(title, value); f.choices = std::move(choices); f.editableChoice = editable; return f;
}
std::filesystem::path pathOf(const QString &value) { return std::filesystem::u8path(u8(value)); }
QString freshNamespace(const std::string &current) {
    if (!current.empty()) return qs(current);
    auto id = randomBytes(16); return qs(hex(id.data(), id.size()));
}
QString prose(const std::string &value) {
    // Provider messages: keep line breaks, replace other control/bidi characters.
    auto out = qs(value);
    for (auto &c : out) {
        auto u = c.unicode();
        if ((u < 32 && u != '\n' && u != '\t') || u == 127 || (u >= 0x202a && u <= 0x202e) || (u >= 0x2066 && u <= 0x2069)) c = QChar(0xfffd);
    }
    return out;
}
}

SafeEndPanel::SafeEndPanel(QWidget *parent, const std::filesystem::path &directory) : QWidget(parent) {
    auto *layout = new QVBoxLayout(this);
    nameSpace = new QLabel(this); nameSpace->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(nameSpace);
    auto button = [&](Action id, const QString &label) { auto *b = new QPushButton(label, this); buttons[id] = b;
        connect(b, &QPushButton::clicked, this, [this, id] { command(id); }); return b; };
    auto *row0 = new QHBoxLayout();
    row0->addWidget(button(Serve, QStringLiteral("启动中转服务"))); row0->addStretch(1);
    layout->addLayout(row0);
    auto *row1 = new QGridLayout();
    row1->addWidget(button(Open, QStringLiteral("打开凭证库")), 0, 0); row1->addWidget(button(Lock, QStringLiteral("停止并锁定")), 0, 1);
    row1->addWidget(button(Refresh, QStringLiteral("刷新")), 0, 2); row1->addWidget(button(Initialize, QStringLiteral("初始化本机库")), 0, 3);
    row1->addWidget(button(Restore, QStringLiteral("从备份恢复")), 0, 4);
    layout->addLayout(row1);
    // Restore never overwrites or merges; backup followed by confirmed clearing
    // makes this action available again.
    buttons[Initialize]->setToolTip(QStringLiteral("本机库尚未初始化、已清空或已解除云端绑定时，可建立新的本机库。"));
    buttons[Restore]->setToolTip(QStringLiteral("本机库尚未初始化、已清空或已解除云端绑定时可用。恢复不会覆盖或合并已有库。"));
    layout->addWidget(new QLabel(QStringLiteral("安全端保存的网站与账号"), this));
    table = new QTableWidget(0, 3, this);
    table->setHorizontalHeaderLabels({QStringLiteral("网站"), QStringLiteral("账号"), QStringLiteral("显示名称")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers); table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->horizontalHeader()->setStretchLastSection(true); table->verticalHeader()->hide();
    layout->addWidget(table, 1);
    auto *row2 = new QGridLayout();
    row2->addWidget(button(Backup, QStringLiteral("创建加密备份")), 0, 0); row2->addWidget(button(ResetPin, QStringLiteral("重置设备中转 PIN")), 0, 1);
    buttons[Backup]->setToolTip(QStringLiteral("成功保存并校验备份后，本机库可选择清空；云端库可选择解除本机绑定，再初始化本机库、从备份恢复或连接云端库。"));
    row2->addWidget(button(RevokeDevice, QStringLiteral("撤销丢失设备")), 0, 2);
    layout->addLayout(row2);
    layout->addWidget(new QLabel(QStringLiteral("云存储"), this));
    auto *row3 = new QGridLayout();
    row3->addWidget(button(Profile, QStringLiteral("配置云存储")), 0, 0); row3->addWidget(button(NewCloud, QStringLiteral("建立云端库")), 0, 1);
    row3->addWidget(button(ExistingCloud, QStringLiteral("连接已有库")), 0, 2); row3->addWidget(button(Migrate, QStringLiteral("迁移到云端")), 0, 3);
    row3->addWidget(button(Resume, QStringLiteral("恢复未完成操作")), 0, 4);
    for (auto id : {NewCloud, ExistingCloud, Migrate})
        buttons[id]->setToolTip(QStringLiteral("请先通过“配置云存储”保存对应凭证库编号的云配置。"));
    layout->addLayout(row3);

    auto dir = directory.empty() ? Storage::defaultDirectory() : directory;
    session = std::make_unique<SafeEndSession>(dir, [this] { QMetaObject::invokeMethod(this, [this] { changed(); }, Qt::QueuedConnection); });
    connect(&SessionMonitor::instance(), &SessionMonitor::locked, this, [this] { lock(); });
    auto *timer = new QTimer(this); connect(timer, &QTimer::timeout, this, &SafeEndPanel::changed); timer->start(250);
    showState();
}
SafeEndPanel::~SafeEndPanel() { session.reset(); }
void SafeEndPanel::shutdown() {
    if (closing) return;
    closing = true; ++epoch; redact = true; table->setRowCount(0);
    session->close();
}
void SafeEndPanel::lock() { ++epoch; redact = true; table->setRowCount(0); session->requestLock(); showState(); }
void SafeEndPanel::changed() {
    if (closing) return;
    handleQuestion(); showState();
    // macOS HID enumeration can pump native/Qt events during MainWindow's
    // constructor. A modal unlock dialog at that point blocks window.show(),
    // leaving both the manager and its child dialog invisible. Wait for the
    // top-level window, even when this panel is on an unselected tab.
    if (!autoChecked && window()->isVisible() && !session->visibleBusy()) {
        autoChecked = true;
        QSettings settings;
        if (settings.value(QStringLiteral("relay/autoServe")).toBool())
            startService(settings.value(QStringLiteral("relay/address"), QStringLiteral("0.0.0.0")).toString(),
                         static_cast<uint16_t>(settings.value(QStringLiteral("relay/port"), 8443).toUInt()));
    }
}
void SafeEndPanel::showState() {
    auto s = session->snapshot(); bool busy = session->visibleBusy(), ready = s.unlocked && !redact, local = s.kind == StorageKind::Local;
    bool unbound = s.kind == StorageKind::Unbound;
    bool pending = s.kind == StorageKind::InitializingCloud || s.kind == StorageKind::MovingToCloud;
    bool configured = !s.cloudProfiles.empty();
    bool matchingProfile = std::find(s.cloudProfiles.begin(), s.cloudProfiles.end(), s.nameSpace) != s.cloudProfiles.end();
    if (!session->busy()) serving = false;
    auto enable = [&](Action id, bool value) { buttons[id]->setEnabled(value && !closing); };
    enable(Open, !busy && !ready && s.initialized && !pending); enable(Lock, busy || ready); enable(Refresh, !busy || serving);
    enable(Initialize, !busy && (local || unbound) && !s.initialized); enable(Restore, !busy && (local || unbound) && !s.initialized);
    enable(Backup, !busy && ready); enable(ResetPin, !busy && ready);
    enable(RevokeDevice, true); // Must stay available while the listener owns the vault.
    enable(Profile, !busy && !ready); enable(NewCloud, !busy && !ready && configured && (local || unbound) && !s.initialized);
    enable(ExistingCloud, !busy && !ready && configured && (local || unbound) && !s.initialized);
    enable(Migrate, !busy && !ready && matchingProfile && local && s.initialized);
    enable(Resume, !busy && !ready && pending);
    // The service button also stops what it started. Green starts, red stops; restyle only on change (setStyleSheet repolishes).
    auto serveText = serving ? QStringLiteral("停止中转服务") : QStringLiteral("启动中转服务");
    if (buttons[Serve]->text() != serveText || buttons[Serve]->styleSheet().isEmpty()) {
        buttons[Serve]->setText(serveText);
        buttons[Serve]->setStyleSheet(QStringLiteral("QPushButton { background: %1; color: white; border: none; border-radius: 4px; padding: 4px 18px; }"
            "QPushButton:disabled { background: palette(button); color: palette(mid); }").arg(serving ? QStringLiteral("#d13b3b") : QStringLiteral("#1f9a1f")));
    }
    enable(Serve, serving || (!busy && s.initialized && !pending));
    if (s.version == shown && busy == shownBusy && redact == shownRedact) return;
    if (unbound) QSettings().setValue(QStringLiteral("relay/autoServe"), false);
    shown = s.version; shownBusy = busy; shownRedact = redact;
    auto kind = unbound ? QStringLiteral("尚未绑定云端库") : local ? QStringLiteral("本机存储") : pending ? QStringLiteral("云端操作待恢复") : QStringLiteral("云端存储");
    auto text = QStringLiteral("中转服务 · ") + kind + (ready ? QStringLiteral(" · 已打开") : QStringLiteral(" · 已锁定")) +
        (serving ? QStringLiteral(" · 服务运行中") : busy ? QStringLiteral(" · 正在处理") : QString()) + QStringLiteral(" · ") + qs(s.status);
    if (text != last) { last = text; emit message(text); }
    nameSpace->setText(s.nameSpace.empty() ? (unbound ? QStringLiteral("凭证库编号：尚未绑定") : QStringLiteral("凭证库编号：尚未初始化")) : QStringLiteral("凭证库编号：") + qs(s.nameSpace));
    table->setRowCount(0);
    if (!redact) for (const auto &row : s.rows) {
        int r = table->rowCount(); table->insertRow(r);
        table->setItem(r, 0, new QTableWidgetItem(safeLabel(row.rp)));
        table->setItem(r, 1, new QTableWidgetItem(safeLabel(row.userName)));
        table->setItem(r, 2, new QTableWidgetItem(safeLabel(row.displayName)));
    }
}
void SafeEndPanel::handleQuestion() {
    if (answering || closing) return;
    EnrollmentQuestion q;
    if (!session->pendingQuestion(q)) return;
    answering = true; auto start = epoch;
    std::string answer; bool accepted = false;
    try {
        if (q.kind == SafeEndSession::CloudRecoveryCodeQuestion) {
            auto secret = enterCode(this, QStringLiteral("打开云端凭证库"), qs(q.message));
            if (secret && start == epoch && !closing && !session->canceled()) {
                answer = secret->remember ? "1" : "0";
                answer.append(secret->value.begin(), secret->value.end()); accepted = true;
            }
        } else if (q.kind == SafeEndSession::ClearLocalAfterBackupQuestion || q.kind == SafeEndSession::DetachCloudAfterBackupQuestion) {
            bool detach = q.kind == SafeEndSession::DetachCloudAfterBackupQuestion;
            QMessageBox box(QMessageBox::Warning, detach ? QStringLiteral("备份成功，要解除本机云端绑定吗？") : QStringLiteral("备份成功，要清空本机库吗？"),
                QStringLiteral("加密备份已保存到：\n") + QDir::toNativeSeparators(qs(q.value)) + QStringLiteral("\n\n") + prose(q.message),
                QMessageBox::NoButton, this);
            box.setTextFormat(Qt::PlainText);
            auto *keep = box.addButton(detach ? QStringLiteral("保留绑定") : QStringLiteral("保留本机库"), QMessageBox::RejectRole);
            auto *clear = box.addButton(detach ? QStringLiteral("解除本机绑定") : QStringLiteral("清空本机库"), QMessageBox::DestructiveRole);
            box.setDefaultButton(keep); box.setEscapeButton(keep);
            box.exec();
            accepted = start == epoch && !closing && !session->canceled();
            answer = box.clickedButton() == clear ? (detach ? "detach" : "clear") : "keep";
        } else {
            QString title = q.kind == 4 ? QStringLiteral("保存云授权配置")
                                                 : QStringLiteral("云盘登录与选择");
            if (q.kind == 1) {
                QVector<FormField> none;
                auto host = qs(q.value.substr(0, q.value.find('/', 8)));
                if (FormDialog::ask(this, title, QStringLiteral("继续将在系统浏览器中打开云盘登录页面。请在那里完成登录和授权，再返回此窗口。\n登录页面：") + host, none) &&
                    start == epoch && !closing) {
                    need(QDesktopServices::openUrl(QUrl(qs(q.value), QUrl::StrictMode)), "无法打开系统浏览器");
                    answer = "opened"; accepted = true;
                }
            } else {
                QVector<FormField> fields;
                auto input = text(QStringLiteral("选择或填写"), qs(q.value), 8192, q.required);
                input.secret = q.secret;
                for (const auto &c : q.choices) input.choices.push_back({qs(c.first), safeLabel(c.second)});
                input.editableChoice = !q.exclusive;
                fields.push_back(input);
                if (FormDialog::ask(this, title, prose(q.message), fields) && start == epoch && !closing) {
                    answer = u8(fields[0].value); accepted = true;
                }
            }
        }
    } catch (...) {} // No provider/OAuth details enter a public error message.
    session->answer(accepted, answer); wipe(answer);
    answering = false;
}
void SafeEndPanel::command(Action id) {
    try {
        if (id == Lock) {
            if (serving) QSettings().setValue(QStringLiteral("relay/autoServe"), false); // stopped by hand
            lock(); return;
        }
        if (id == Serve) { serve(); return; }
        if (id == RevokeDevice) { revokeDevice(); return; }
        if (id == Refresh && serving) { session->requestRows(); return; } // the service owns the vault
        if (session->visibleBusy() || closing) return;
        auto start = epoch; auto *s = session.get();
        if (id >= NewCloud && id <= Resume) { cloudAction(id); return; }
        if (id == Profile) { profileAction(); return; }
        if (id == Open || id == Initialize) {
            redact = false;
            s->submit([s, id] { s->publish("正在打开凭证库…");
                if (id == Initialize) s->storage().initializeLocal();
                s->acquireRemembered(); s->publish("凭证库已打开；列表仅显示在安全端。", true); });
            return;
        }
        if (id == Refresh) { s->submit([s] { s->readState(); s->publish("存储状态已更新。", s->vault() != nullptr); }); return; }
        if (id == Backup || id == Restore) {
            auto file = id == Backup
                ? QFileDialog::getSaveFileName(this, QStringLiteral("创建加密备份"), QStringLiteral("safe-end.pf2bak"), QStringLiteral("加密凭证库备份 (*.pf2bak);;所有文件 (*)"), nullptr, QFileDialog::DontConfirmOverwrite)
                : QFileDialog::getOpenFileName(this, QStringLiteral("从备份恢复"), {}, QStringLiteral("加密凭证库备份 (*.pf2bak);;所有文件 (*)"));
            if (file.isEmpty() || start != epoch || closing) return;
            auto path = pathOf(file);
            need(id != Backup || !std::filesystem::exists(path), "目标文件已存在；请选择新的文件名");
            auto secret = password(this, id == Backup ? QStringLiteral("设置备份密码") : QStringLiteral("解锁备份文件"), id == Backup);
            if (!secret || start != epoch || closing) return;
            if (id == Restore) redact = false;
            s->submit([s, id, path, secret] {
                s->publish(id == Backup ? "正在加密并写入备份…" : "正在验证并恢复备份…");
                if (id == Backup) s->exportBackup(path, secret->value);
                else { s->storage().restoreLocal(path, secret->value); s->acquire(L""); s->publish("备份已恢复，凭证、计数器和 PIN 状态已保留。", true); }
            });
            return;
        }
        if (id == ResetPin) {
            QVector<FormField> fields{text(QStringLiteral("设备序列号"), {}, 16)};
            if (!FormDialog::ask(this, QStringLiteral("重置设备的中转 PIN"),
                    QStringLiteral("仅清除此设备在安全端的 PIN 与重试状态。凭证保留；设备下次需要重新设置中转 PIN。"), fields) ||
                start != epoch || closing) return;
            auto value = u8(fields[0].value);
            s->submit([s, value] {
                need(s->vault() != nullptr, "请先打开凭证库"); s->vault()->resetDevicePin(value);
                s->publish("中转 PIN 已清除，凭证仍保留。请在设备上设置新的中转 PIN。");
            });
            return;
        }
    } catch (const std::exception &e) { showError(this, QStringLiteral("中转模式服务"), e); }
}
void SafeEndPanel::serve() {
    if (serving) {
        QSettings().setValue(QStringLiteral("relay/autoServe"), false); // stopped by hand
        lock(); return;
    }
    if (session->visibleBusy() || closing) return;
    auto start = epoch; QSettings settings;
    QVector<FormField> fields{text(QStringLiteral("监听地址"), settings.value(QStringLiteral("relay/address"), QStringLiteral("0.0.0.0")).toString()),
                              text(QStringLiteral("端口"), settings.value(QStringLiteral("relay/port"), 8443).toString(), 5)};
    ClearFields clear{fields};
    if (!FormDialog::ask(this, QStringLiteral("启动中转服务"),
            QStringLiteral("服务只接受本机配对过的设备，每次请求均需批准。启动后打开软件会自动启动服务；停止服务可关闭自动启动，锁屏会暂停服务。"),
            fields, [](const QVector<QString> &values) {
                bool ok = false; auto port = values[1].toUInt(&ok);
                if (!ok || !port || port > 65535) return QStringLiteral("端口应为 1–65535。");
                return QString();
            }) || start != epoch || closing) return;
    auto n = fields[1].value.toUInt();
    settings.setValue(QStringLiteral("relay/address"), fields[0].value);
    settings.setValue(QStringLiteral("relay/port"), n);
    startService(fields[0].value, static_cast<uint16_t>(n));
}
void SafeEndPanel::startService(const QString &address, uint16_t port) {
    auto *s = session.get(); auto state = s->snapshot(); auto start = epoch;
    if (s->visibleBusy() || closing || !port || !state.initialized ||
        state.kind == StorageKind::InitializingCloud || state.kind == StorageKind::MovingToCloud) return;
    bool open = state.unlocked && !redact;
    redact = false;
    auto host = u8(address);
    serving = s->submit([this, s, open, host, port, start] {
        if (!open) { s->acquireRemembered(); s->publish("凭证库已打开，正在启动服务…", true); }
        serveRelay(*s, host, port, approveOnGui, [this, start](uint16_t) {
            // Canceling the unlock prompt must not enable automatic startup.
            QMetaObject::invokeMethod(this, [this, start] {
                if (start == epoch && !closing && !session->canceled())
                    QSettings().setValue(QStringLiteral("relay/autoServe"), true);
            }, Qt::QueuedConnection);
        });
    });
    showState();
}
void SafeEndPanel::cloudAction(Action id) {
    auto start = epoch; auto *s = session.get();
    auto state = s->snapshot(); auto ns = state.nameSpace;
    bool selecting = id == NewCloud || id == ExistingCloud, creating = id == NewCloud || id == Migrate;
    auto secret = std::make_shared<Secret>(); QVector<FormField> fields;
    ClearFields clear{fields};
    if (selecting) {
        need(!state.cloudProfiles.empty(), "请先配置云存储");
        QVector<QPair<QString, QString>> profiles;
        for (const auto &name : state.cloudProfiles) profiles.push_back({qs(name), qs(name)});
        if (std::find(state.cloudProfiles.begin(), state.cloudProfiles.end(), ns) == state.cloudProfiles.end()) ns = state.cloudProfiles.front();
        fields.push_back(choice(QStringLiteral("凭证库编号"), qs(ns), profiles));
    }
    if (creating) {
        secret->value = backup::newRecoveryCode();
        fields.push_back(text(QStringLiteral("新库恢复码（请保存）"), qs(backup::displayRecoveryCode(secret->value)), 64, true, true));
    }
    fields.push_back(secretField(creating ? QStringLiteral("重新输入恢复码确认") : QStringLiteral("恢复码"), 64));
    const int codeIndex = fields.size() - 1;
    fields.push_back(rememberCode());
    auto title = id == NewCloud ? QStringLiteral("建立云端凭证库") : id == ExistingCloud ? QStringLiteral("连接已有云端凭证库") :
                 id == Migrate ? QStringLiteral("迁移到云端") : QStringLiteral("恢复未完成的云端操作");
    auto hint = creating ? QStringLiteral("请先抄写或打印新库恢复码并离线保存，再在下方输入一次确认。打开库、换电脑或恢复未完成操作时都需要它；丢失后无法找回。")
                         : QStringLiteral("填写此云端库的恢复码，大小写、空格和横线均可。库编号和云配置必须属于同一份凭证库。");
    if (id == Migrate) hint += QStringLiteral("\n迁移保留全部凭证、计数器与 PIN 状态，并停用旧本机副本。");
    if (!FormDialog::ask(this, title, hint, fields, [&](const QVector<QString> &values) {
        if (selecting) try { (void)CloudStorage::identity(u8(values[0])); }
            catch (...) { return QStringLiteral("凭证库编号应为 32 位小写十六进制字符，且不能全为零。"); }
        try {
            Secret check{recovery(values[codeIndex])};
            if (creating && check.value != secret->value) return QStringLiteral("输入的恢复码与生成的不一致，请核对后重新输入。");
        } catch (...) { return QStringLiteral("恢复码格式不正确，请输入完整的 26 位恢复码。"); }
        return QString();
    }) || start != epoch || closing) return;
    if (selecting) ns = u8(fields[0].value);
    if (!creating) secret->value = recovery(fields[codeIndex].value);
    secret->remember = fields.back().value == QStringLiteral("1");
    redact = false;
    s->submit([s, id, ns, secret] {
        s->resetStorage(); auto &storage = s->storage();
        s->publish(id == Migrate ? "正在迁移；完成前请保持窗口打开。旧副本将在发布云端数据前停用。" : "正在连接并验证云端存储…");
        if (id == NewCloud) storage.initializeCloud(ns, secret->value);
        else if (id == ExistingCloud) storage.selectCloud(ns, secret->value);
        else if (id == Migrate) storage.migrateCloud(secret->value);
        else storage.resume(secret->value);
        s->acquire(secret->value);
        need(!s->canceled(), "操作已取消");
        if (secret->remember) storage.rememberCloudCode(secret->value);
        else storage.forgetCloudCode();
        s->publish("云端库已打开；每次中转请求仍需单独批准。", true);
    });
}
void SafeEndPanel::profileAction() {
    auto start = epoch; auto *s = session.get(); auto state = s->snapshot();
    QVector<FormField> f;
    ClearFields clear{f};
    using Visible = std::function<bool(const QVector<QString> &)>;
    auto add = [&](FormField field, Visible visible = {}) {
        field.visibleWhen = std::move(visible); f.push_back(std::move(field)); return f.size() - 1;
    };
    const int action = add(choice(QStringLiteral("操作"), state.kind == StorageKind::Cloud ? QStringLiteral("update") : QStringLiteral("onedrive"), {
        {QStringLiteral("onedrive"), QStringLiteral("新建 OneDrive 配置")}, {QStringLiteral("drive"), QStringLiteral("新建 Google Drive 配置")},
        {QStringLiteral("webdav"), QStringLiteral("新建 WebDAV 配置")}, {QStringLiteral("update"), QStringLiteral("更新现有配置或重新登录")}}));
    auto updating = [=](const QVector<QString> &v) { return v[action] == QStringLiteral("update"); };
    auto creating = [=](const QVector<QString> &v) { return !updating(v); };
    const int update = add(choice(QStringLiteral("更新内容"), QStringLiteral("oauth"), {
        {QStringLiteral("oauth"), QStringLiteral("OneDrive / Google Drive 重新登录")}, {QStringLiteral("webdav"), QStringLiteral("WebDAV 密码或访问令牌")},
        {QStringLiteral("coordinator"), QStringLiteral("协调服务器连接与证书")},
        {QStringLiteral("oauth-coordinator"), QStringLiteral("云盘重新登录 + 协调端换证")},
        {QStringLiteral("webdav-coordinator"), QStringLiteral("WebDAV 凭据更新 + 协调端换证")}}), updating);
    auto webdav = [=](const QVector<QString> &v) {
        return v[action] == QStringLiteral("webdav") || (updating(v) && v[update].startsWith(QStringLiteral("webdav")));
    };
    auto oauth = [=](const QVector<QString> &v) {
        return v[action] == QStringLiteral("onedrive") || v[action] == QStringLiteral("drive") ||
            (updating(v) && v[update].startsWith(QStringLiteral("oauth")));
    };
    auto coordinator = [=](const QVector<QString> &v) { return creating(v) || v[update].endsWith(QStringLiteral("coordinator")); };
    // Creation proposes a fresh ID; updating never guesses one for an unbound host.
    const int freshNs = add(text(QStringLiteral("凭证库编号"), freshNamespace(state.nameSpace), 32, true, !state.nameSpace.empty()), creating);
    const int currentNs = add(text(QStringLiteral("凭证库编号"), qs(state.nameSpace), 32, true, !state.nameSpace.empty()), updating);
    auto nsOf = [=](const QVector<QString> &v) { return updating(v) ? currentNs : freshNs; };
    const int root = add(text(QStringLiteral("云端目录"), QStringLiteral("pico-fido2")), creating);
    const int url = add(text(QStringLiteral("WebDAV 地址"), QStringLiteral("https://")), [=](const auto &v) { return v[action] == QStringLiteral("webdav"); });
    const int user = add(text(QStringLiteral("用户名")), [=](const auto &v) { return v[action] == QStringLiteral("webdav"); });
    const int pass = add(secretField(QStringLiteral("WebDAV 密码或访问令牌")), webdav);
    const int repeat = add(secretField(QStringLiteral("再次输入")), [=](const auto &v) { return updating(v) && webdav(v); });
    const int appId = add(text(QStringLiteral("应用 Client ID"), {}, 512, false), oauth);
    const int appSecret = add(secretField(QStringLiteral("应用密钥"), 1024, false), oauth);
    const int scope = add(choice(QStringLiteral("Google Drive 权限"), QStringLiteral("drive.file"), {
        {QStringLiteral("drive.file"), QStringLiteral("仅此应用创建或打开的文件")}, {QStringLiteral("drive"), QStringLiteral("完整云盘读写（含共享云盘）")}}),
        [=](const auto &v) { return v[action] == QStringLiteral("drive"); });
    const int region = add(choice(QStringLiteral("微软云区域"), QStringLiteral("global"), {
        {QStringLiteral("global"), QStringLiteral("全球")}, {QStringLiteral("us"), QStringLiteral("美国政府云")},
        {QStringLiteral("de"), QStringLiteral("德国云")}, {QStringLiteral("cn"), QStringLiteral("中国云")}}),
        [=](const auto &v) { return v[action] == QStringLiteral("onedrive"); });
    const int endpoint = add(text(QStringLiteral("协调服务器地址"), QStringLiteral("https://")), coordinator);
    const int ca = add(fileField(QStringLiteral("协调服务器 CA")), coordinator);
    const int cert = add(fileField(QStringLiteral("客户端证书")), coordinator);
    const int key = add(fileField(QStringLiteral("客户端私钥")), coordinator);
    const int providerCa = add(fileField(QStringLiteral("WebDAV CA（可选）"), false), webdav);
    if (!FormDialog::ask(this, QStringLiteral("配置云存储"),
            QStringLiteral("选择操作后填写下方配置。OneDrive 的应用凭据可留空；Google Drive 新配置需填写自己的 Client ID 和密钥。"
                           "更新时留空表示沿用现有应用凭据。更新不会更改原云盘、目录或协调集群；云盘登录与最终保存会在需要时继续确认。"), f,
            [&](const QVector<QString> &v) {
                try { (void)CloudStorage::identity(u8(v[nsOf(v)])); }
                catch (...) { return QStringLiteral("凭证库编号应为 32 位小写十六进制字符，且不能全为零。"); }
                if (v[action] == QStringLiteral("drive") && (v[appId].isEmpty() || v[appSecret].isEmpty()))
                    return QStringLiteral("新建 Google Drive 配置需要填写应用 Client ID 和密钥。");
                if (updating(v) && webdav(v) && v[pass] != v[repeat]) return QStringLiteral("两次输入的 WebDAV 凭据不一致。");
                for (int i : {url, endpoint}) if (!f[i].visibleWhen || f[i].visibleWhen(v)) {
                    QUrl address(v[i], QUrl::StrictMode);
                    if (!address.isValid() || address.scheme() != QStringLiteral("https") || address.host().isEmpty())
                        return QStringLiteral("“%1”应填写完整的 HTTPS 地址。").arg(f[i].title);
                }
                for (int i : {ca, cert, key, providerCa}) if ((!f[i].visibleWhen || f[i].visibleWhen(v)) && !v[i].isEmpty()) {
                    std::error_code error;
                    if (!std::filesystem::is_regular_file(pathOf(v[i]), error))
                        return QStringLiteral("找不到“%1”文件，请检查路径或点击“浏览”。").arg(f[i].title);
                }
                return QString();
            }) || start != epoch || closing) return;
    const auto provider = u8(f[action].value), name = u8(f[provider == "update" ? currentNs : freshNs].value);
    auto takeCoordinator = [&](CloudProfileFields &p) {
        p.coordinator = u8(f[endpoint].value); p.ca = pathOf(f[ca].value);
        p.certificate = pathOf(f[cert].value); p.privateKey = pathOf(f[key].value);
    };
    if (provider == "update") {
        auto p = std::make_shared<ProfileMaintenance>(); p->action = u8(f[update].value);
        bool combined = p->action == "oauth-coordinator" || p->action == "webdav-coordinator";
        if (combined) p->action.resize(p->action.find('-'));
        if (p->action == "oauth") { p->clientId = u8(f[appId].value); p->clientSecret = ws(f[appSecret].value); }
        else if (p->action == "webdav") {
            p->secret = ws(f[pass].value);
            if (!f[providerCa].value.isEmpty()) p->providerCa = pathOf(f[providerCa].value);
        }
        if (combined || p->action == "coordinator") takeCoordinator(p->coordinator);
        s->submit([s, p, name] {
            (void)s->storage().choice();
            s->publish("正在锁定并验证现有云配置…");
            auto request = profileMaintenancePatch(*p); struct Clear { Bytes &b; ~Clear() { wipe(b); } } clear{request};
            CloudStorage::updateProfile(name, request, [s](const EnrollmentQuestion &question) {
                s->publish(question.kind == 1 ? "请在浏览器中完成重新登录。" : "请确认原云盘及配置更新；可取消保留原配置。");
                return s->ask(question);
            }, s->launch());
            s->publish("云配置已更新，凭证库保持锁定。可以重新打开，或继续先前未完成的操作。");
        });
    } else if (provider == "webdav") {
        auto p = std::make_shared<WebDavProfile>(); p->nameSpace = name; p->root = u8(f[root].value);
        p->url = u8(f[url].value); p->user = u8(f[user].value); p->password = ws(f[pass].value); takeCoordinator(*p);
        if (!f[providerCa].value.isEmpty()) p->providerCa = pathOf(f[providerCa].value);
        s->submit([s, p] {
            (void)s->storage().choice();
            s->publish("正在验证协调服务器身份并保存云配置…");
            auto request = webDavProfileSetup(*p); struct Clear { Bytes &b; ~Clear() { wipe(b); } } clear{request};
            CloudStorage::saveProfile(p->nameSpace, request, s->launch());
            s->setNamespace(p->nameSpace); s->publish("云配置已保存。现在可以建立、连接或迁移该编号的凭证库。");
        });
    } else {
        auto p = std::make_shared<OAuthProfile>(); p->provider = provider; p->nameSpace = name; p->root = u8(f[root].value);
        p->clientId = u8(f[appId].value); p->clientSecret = ws(f[appSecret].value); takeCoordinator(*p);
        p->scopeOrRegion = u8(f[provider == "drive" ? scope : region].value);
        s->submit([s, p] {
            (void)s->storage().choice();
            s->publish("正在验证协调服务器并准备云盘登录…");
            auto request = oauthProfileSetup(*p); struct Clear { Bytes &b; ~Clear() { wipe(b); } } clear{request};
            CloudStorage::enrollProfile(p->nameSpace, request, [s](const EnrollmentQuestion &question) {
                s->publish(question.kind == 1 ? "请在浏览器中完成云盘登录；可随时停止并锁定以取消。" : "请确认云盘选择和配置保存。");
                return s->ask(question);
            }, s->launch());
            s->setNamespace(p->nameSpace); s->publish("云授权配置已保存。现在可以建立、连接或迁移该编号的凭证库。");
        });
    }
}
void SafeEndPanel::revokeDevice() {
    auto start = epoch;
    QVector<QPair<QString, QString>> choices;
    for (const auto &serial : relayTrustedDevices()) {
        std::wstring name; try { name = loadDeviceName(serial); } catch (...) {}
        choices.push_back({qs(serial), (name.empty() ? QString() : qs(name) + QStringLiteral(" · ")) + qs(serial)});
    }
    need(!choices.isEmpty(), "此安全端没有已配对的中转设备");
    QVector<FormField> f{choice(QStringLiteral("丢失的设备"), {}, choices)};
    if (!FormDialog::ask(this, QStringLiteral("撤销丢失设备的中转授权"),
            QStringLiteral("无需插入密钥。删除此设备在本机的公钥后，安全端持续拒绝它的新请求并取消尚未完成的审批；不删除账号，也不影响其他设备。"
                           "找回设备后按 BOOT 重新配对即可恢复。"), f) ||
        start != epoch || closing) return;
    auto serial = u8(f[0].value);
    if (QMessageBox::warning(this, QStringLiteral("撤销中转授权"), QStringLiteral("确认撤销设备 %1？\n此操作不会删除凭证或公用服务证书。").arg(qs(serial)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes || start != epoch || closing) return;
    forgetRelayDevice(serial);
    QMessageBox::information(this, QStringLiteral("撤销完成"), QStringLiteral("已删除此设备的公钥，安全端不再接受它的请求。"));
}
