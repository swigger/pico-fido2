#include "device_settings_panel.h"
#include "widgets.h"
#include <QComboBox>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <algorithm>
#include <cstring>

namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
QString networkText(const RelayStatus &s) {
    if (!s.network || !s.networkPhase) return {};
    static const char *phases[] = {"", "初始化 Wi-Fi", "连接 Wi-Fi", "等待地址", "解析并连接安全端", "（保留）",
                                   "TLS 握手", "发送请求", "等待安全端", "已完成"};
    QString phase = s.networkPhase < 10 ? qs(phases[s.networkPhase]) : QStringLiteral("未知阶段 %1").arg(s.networkPhase);
    QString flags;
    if (s.networkFlags & 2) flags += QStringLiteral(" · 已关联");
    if (s.networkFlags & 4) flags += QStringLiteral(" · IPv4");
    if (s.networkFlags & 8) flags += QStringLiteral(" · IPv6");
    auto text = QStringLiteral("最近一次中转连接：第 %1 组网络 · %2%3").arg(s.networkProfile).arg(phase, flags);
    if (s.wifiReason) text += QStringLiteral(" · Wi-Fi 断开原因 %1").arg(s.wifiReason);
    return text;
}
QString ssidOf(const relay_network_t &n) { return qs(std::string(reinterpret_cast<const char *>(n.ssid), n.ssid_length)); }
}

DeviceSettingsPanel::DeviceSettingsPanel(QWidget *parent) : QWidget(parent) {
    auto *grid = new QGridLayout(this);
    mode = new QComboBox(this);
    mode->addItem(QStringLiteral("独立工作模式（默认）")); mode->addItem(QStringLiteral("中转模式"));
    read = new QPushButton(QStringLiteral("读取设备"), this);
    write = new QPushButton(QStringLiteral("写入设备"), this);
    write->setStyleSheet(QStringLiteral("QPushButton { background: #d13b3b; color: white; border: none; border-radius: 4px; padding: 4px 18px; }"
                                        "QPushButton:disabled { background: palette(button); color: palette(mid); }"));
    profiles = new QListWidget(this);
    add = new QPushButton(QStringLiteral("添加"), this); edit = new QPushButton(QStringLiteral("修改"), this);
    remove = new QPushButton(QStringLiteral("移除"), this);
    grid->addWidget(new QLabel(QStringLiteral("工作模式"), this), 0, 0);
    grid->addWidget(mode, 0, 1); grid->addWidget(read, 0, 2); grid->addWidget(write, 0, 3);
    grid->addWidget(new QLabel(QStringLiteral("网络设置"), this), 1, 0, Qt::AlignTop);
    grid->addWidget(profiles, 1, 1);
    auto *buttons = new QVBoxLayout();
    for (auto *b : {add, edit, remove}) buttons->addWidget(b);
    buttons->addStretch(1);
    grid->addLayout(buttons, 1, 2, 1, 2);
    grid->setColumnStretch(1, 1);
    autoRestart = new QCheckBox(QStringLiteral("写入成功后自动重启"), this); autoRestart->setChecked(true);
    restartButton = new QPushButton(QStringLiteral("重启设备"), this);
    grid->addWidget(autoRestart, 2, 1); grid->addWidget(restartButton, 2, 2);
    connect(restartButton, &QPushButton::clicked, this, &DeviceSettingsPanel::restartDevice);

    connect(read, &QPushButton::clicked, this, &DeviceSettingsPanel::readDevice);
    connect(write, &QPushButton::clicked, this, &DeviceSettingsPanel::writeOrCancel);
    connect(add, &QPushButton::clicked, this, [this] { editNetwork(-1); });
    connect(edit, &QPushButton::clicked, this, [this] { editNetwork(profiles->currentRow()); });
    connect(profiles, &QListWidget::itemDoubleClicked, this, [this] { if (usable) editNetwork(profiles->currentRow()); });
    connect(remove, &QPushButton::clicked, this, &DeviceSettingsPanel::removeNetwork);
    connect(profiles, &QListWidget::currentRowChanged, this, [this](int) { refresh(); });
    connect(mode, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
        draft.mode = index == 1 ? RELAY_MODE_RELAY : RELAY_MODE_LOCAL; persist();
    });
    refresh();
}
DeviceSettingsPanel::~DeviceSettingsPanel() { relay_config_clear(&draft); }
void DeviceSettingsPanel::sync(Device *d, const Key *k, bool u) {
    device = d; key = k; usable = u;
    auto current = d ? d->serial : std::string();
    if (current != serial) {
        if (waiting) { waiting = false; emit message(QStringLiteral("设备已断开，无法确认设置是否写入。重新连接后请查看设备状态。")); }
        state.reset(); lastNetwork.clear(); ticks = 0;
        load(current);
    }
    refresh();
}
void DeviceSettingsPanel::poll() {
    if (device && (waiting || ticks++ % 3 == 0)) { check(); refresh(); }
}
void DeviceSettingsPanel::load(const std::string &next) {
    serial = next;
    relay_config_clear(&draft);
    if (!serial.empty()) {
        // An unreadable draft (older format, corruption) is only this computer's
        // copy; the next edit replaces it and the device's settings are unaffected.
        try { loadRelayDraft(serial, draft); }
        catch (const std::exception &e) {
            relay_config_clear(&draft);
            emit message(QStringLiteral("本机保存的设置草稿无法读取（%1），已从空白开始；设备中已写入的设置不受影响。").arg(safeLabel(e.what())));
        }
    }
    mode->setCurrentIndex(draft.mode == RELAY_MODE_RELAY ? 1 : 0);
    list(draft.network_count ? 0 : -1);
}
void DeviceSettingsPanel::list(int row) {
    profiles->blockSignals(true);
    profiles->clear();
    for (unsigned i = 0; i < draft.network_count; ++i)
        profiles->addItem(QStringLiteral("%1. ").arg(i + 1) + ssidOf(draft.networks[i]));
    profiles->setCurrentRow(row);
    profiles->blockSignals(false);
    refresh();
}
void DeviceSettingsPanel::refresh() {
    bool editable = usable && device && !waiting, selected = profiles->currentRow() >= 0;
    mode->setEnabled(editable);
    add->setEnabled(editable && draft.network_count < RELAY_MAX_NETWORKS);
    edit->setEnabled(editable && selected); remove->setEnabled(editable && selected);
    bool ready = state && (state->flags & RELAY_HID_STORAGE_READY) && !state->active();
    read->setEnabled(editable && ready);
    write->setText(waiting ? QStringLiteral("取消写入") : QStringLiteral("写入设备"));
    write->setEnabled(waiting || (editable && key && ready));
    restartButton->setEnabled(editable && key && state && state->canRestart && !state->active());
    autoRestart->setEnabled(!waiting);
}
void DeviceSettingsPanel::persist() {
    try { saveRelayDraft(serial, draft); }
    catch (const std::exception &e) { emit message(safeLabel(e.what())); }
}
void DeviceSettingsPanel::editNetwork(int index) {
    if (!usable || waiting || serial.empty() || index >= static_cast<int>(draft.network_count) ||
        (index < 0 && draft.network_count >= RELAY_MAX_NETWORKS)) return;
    auto owner = serial;
    auto title = index < 0 ? QStringLiteral("添加网络") : QStringLiteral("修改网络");
    relay_network_t n = index >= 0 ? draft.networks[index] : relay_network_t{};
    QVector<FormField> f(4);
    f[0].title = QStringLiteral("Wi-Fi 名称"); f[0].limit = 32; f[0].value = ssidOf(n);
    std::string secret(n.password, n.password_length);
    f[1].title = QStringLiteral("Wi-Fi 密码"); f[1].limit = RELAY_MAX_PASSWORD; f[1].secret = true; f[1].required = false; f[1].value = qs(secret);
    wipe(secret);
    f[2].title = QStringLiteral("安全端主机"); f[2].limit = 253; f[2].value = qs(std::string(n.host, n.host_length));
    f[3].title = QStringLiteral("安全端端口"); f[3].limit = 5; f[3].value = QString::number(n.port ? n.port : 8443);
    secureZero(&n, sizeof(n));
    std::string s, pw, h; unsigned long number = 0;
    for (;;) {
        bool accepted = FormDialog::ask(this, title,
            QStringLiteral("安全端主机填写 DNS 名称或 IP，不包含 https:// 或路径。设备凭配对的本机密钥识别安全端，无需证书。"
                           "密码栏若显示 PF2PW1 开头的加密串，请保留它；要换密码时直接输入新密码。"), f);
        if (!accepted || serial != owner || waiting) { f[1].value.fill(QChar(0)); return; } // device changed while editing
        s = u8(f[0].value); pw = u8(f[1].value); h = u8(f[2].value); auto po = u8(f[3].value);
        bool passwordOk = pw.size() <= RELAY_MAX_PASSWORD;
        if (passwordOk && pw.size() > RELAY_MAX_PASSWORD_PLAIN)
            passwordOk = relay_config_password_token(pw.data(), pw.size());
        bool valid = !s.empty() && s.size() <= 32 && passwordOk && !h.empty() && h.size() <= 253 &&
            !po.empty() && po.size() <= 5 && std::all_of(po.begin(), po.end(), [](char ch) { return ch >= '0' && ch <= '9'; });
        number = valid ? std::stoul(po) : 0;
        if (valid && number > 0 && number <= 65535) break;
        wipe(pw);
        QMessageBox::information(this, title,
            QStringLiteral("请填写 Wi-Fi 名称、安全端主机名与 1–65535 端口。密码可留空、为 8–63 位字符、64 位十六进制 PSK，或保留“读取设备”得到的加密串。"));
    }
    f[1].value.fill(QChar(0));
    n.ssid_length = static_cast<uint8_t>(s.size()); memcpy(n.ssid, s.data(), s.size());
    n.password_length = static_cast<uint8_t>(pw.size()); memcpy(n.password, pw.data(), pw.size());
    n.host_length = static_cast<uint8_t>(h.size()); memcpy(n.host, h.data(), h.size());
    n.port = static_cast<uint16_t>(number);
    wipe(pw);
    int row = index < 0 ? draft.network_count++ : index;
    draft.networks[row] = n; secureZero(&n, sizeof(n));
    persist(); list(row);
}
void DeviceSettingsPanel::removeNetwork() {
    int row = profiles->currentRow();
    if (!usable || waiting || row < 0 || row >= static_cast<int>(draft.network_count)) return;
    for (int i = row; i + 1 < draft.network_count; ++i) draft.networks[i] = draft.networks[i + 1];
    --draft.network_count; secureZero(&draft.networks[draft.network_count], sizeof(relay_network_t));
    persist(); list(draft.network_count ? std::min(row, int(draft.network_count) - 1) : -1);
}
void DeviceSettingsPanel::readDevice() {
    if (waiting || !device || !usable) return;
    try {
        RelayControl control(*device);
        auto s = control.status();
        require((s.flags & RELAY_HID_STORAGE_READY) != 0, "设备配置存储不可用");
        require(!s.active(), "设备正在写入设置，无法读取");
        relay_config_t loaded = control.readConfig();
        relay_config_clear(&draft);
        draft = loaded;
        relay_config_clear(&loaded);
        mode->setCurrentIndex(draft.mode == RELAY_MODE_RELAY ? 1 : 0);
        persist();
        list(draft.network_count ? 0 : -1);
        emit message(QStringLiteral("已读取设备设置：%1 组网络。密码显示为设备加密串，修改后可直接写回；本机草稿已更新。")
            .arg(static_cast<unsigned>(draft.network_count)));
    } catch (const std::exception &e) {
        emit message(safeLabel(e.what()));
        showError(this, QStringLiteral("读取设备"), e);
    }
    refresh();
}
void DeviceSettingsPanel::writeOrCancel() {
    if (waiting) { cancel(); return; }
    try { stage(); }
    catch (const std::exception &e) { emit message(safeLabel(e.what())); showError(this, QStringLiteral("写入设备"), e); }
    refresh();
}
void DeviceSettingsPanel::stage() {
    if (waiting || !device || !key || !usable) return;
    RelayControl control(*device);
    require(control.status().flags & RELAY_HID_STORAGE_READY, "设备配置存储不可用");
    draft.mode = mode->currentIndex() == 1 ? RELAY_MODE_RELAY : RELAY_MODE_LOCAL;
    require(draft.mode != RELAY_MODE_RELAY || !relayDeviceKey(serial).empty(),
        "本机尚未记下此设备的公钥（或已撤销）。请先按 BOOT 重新配对，再启用中转模式");
    require(relay_config_validate(&draft) == RELAY_CONFIG_OK,
        "配置不完整：中转模式至少需要一组网络；Wi-Fi 密码须为空、8–63 位字符、64 位十六进制 PSK，或设备读取的加密串");
    // Keep a recoverable protected copy before a physical commit could succeed.
    // This file is a draft, never device authority.
    saveRelayDraft(serial, draft);
    emit message(QStringLiteral("正在发送并验证配置…"));
    ticket = control.stage(draft, *key);
    waiting = true;
    emit message(QStringLiteral("请先松开 BOOT，再按住至少 1 秒后松开。保存后将按下方选项自动重启，使新配置生效。"));
}
void DeviceSettingsPanel::check() {
    try {
        RelayControl control(*device);
        if (waiting && control.completed(ticket)) {
            waiting = false;
            state = control.status();
            if (autoRestart->isChecked() && key && state->canRestart) {
                try { control.reboot(*key); emit message(QStringLiteral("配置已保存并核对，设备正在重启；新配置将在重新连接后生效。")); }
                catch (const std::exception &e) { emit message(QStringLiteral("配置已保存，但自动重启未获确认：") + safeLabel(e.what()) + QStringLiteral("。请点击重启设备或手动拔插。")); }
                return;
            }
            emit message(QStringLiteral("配置已保存并核对一致。请点击“重启设备”或拔插设备启用新配置。"));
        }
        state = control.status();
        auto network = networkText(*state);
        if (!network.isEmpty() && !lastNetwork.isEmpty() && network != lastNetwork) emit message(network);
        lastNetwork = network.isEmpty() ? QStringLiteral(" ") : network;
    } catch (const std::exception &e) {
        if (waiting) {
            try { RelayControl(*device).cancel(ticket.transaction); } catch (...) {}
            waiting = false; emit message(safeLabel(e.what()));
        } else state.reset();
    }
}
void DeviceSettingsPanel::restartDevice() {
    if (!device || !key || !usable || waiting) return;
    try { RelayControl(*device).reboot(*key); emit message(QStringLiteral("设备已接受重启指令，正在重新连接；已保存的配置将生效。")); }
    catch (const std::exception &e) { showError(this, QStringLiteral("重启设备"), e); }
}
void DeviceSettingsPanel::cancel() {
    if (!waiting) return;
    waiting = false;
    try {
        if (device) RelayControl(*device).cancel(ticket.transaction);
        emit message(QStringLiteral("已取消写入，设备设置未改变。"));
    } catch (const std::exception &e) { emit message(safeLabel(e.what())); }
    refresh();
}
