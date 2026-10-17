#include "flash_dialog.h"
#include "widgets.h"
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace {
QLabel *wrapped(const QString &text, QWidget *parent) {
    auto *label = new QLabel(text, parent); label->setWordWrap(true); label->setTextFormat(Qt::PlainText); return label;
}
}

QString FlashDialog::bundledImage() {
    QDir dir(QCoreApplication::applicationDirPath());
#ifdef __APPLE__
    dir.cd(QStringLiteral("../Resources")); // non-code files live in the bundle's Resources
#endif
    auto found = dir.entryList({QStringLiteral("esp32s3supermini-*.bin")}, QDir::Files, QDir::Name | QDir::Reversed);
    return found.isEmpty() ? QString() : QDir::toNativeSeparators(dir.filePath(found.first()));
}

FlashDialog::FlashDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("刷写新设备"));
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(wrapped(QStringLiteral(
        "将固件写入一块 ESP32-S3 SuperMini（目前仅支持 ESP32-S3）。\n"
        "1. 拔下设备，按住 BOOT 键插入 USB，然后松开 BOOT，设备即进入下载模式。\n"
        "2. 下方显示已发现设备后，勾选确认并开始刷写。完成后设备自动重启，即可在主窗口中选择、命名并配对。"), this));
    auto *grid = new QGridLayout();
    image = new QLineEdit(bundledImage(), this); image->setReadOnly(true);
    image->setPlaceholderText(QStringLiteral("未附带固件，请选择 esp32s3supermini-*.bin"));
    choose = new QPushButton(QStringLiteral("选择…"), this);
    ports = new QComboBox(this);
    portHint = wrapped({}, this);
    grid->addWidget(new QLabel(QStringLiteral("固件"), this), 0, 0); grid->addWidget(image, 0, 1); grid->addWidget(choose, 0, 2);
    grid->addWidget(new QLabel(QStringLiteral("设备"), this), 1, 0); grid->addWidget(ports, 1, 1, 1, 2);
    grid->addWidget(portHint, 2, 1, 1, 2);
    grid->setColumnStretch(1, 1);
    layout->addLayout(grid);
    auto *warning = wrapped(QStringLiteral("警告：刷写会清除芯片上现有的所有数据，包括通行密钥、配对关系和网络设置，且无法恢复。本工具不做任何备份。"), this);
    warning->setStyleSheet(QStringLiteral("color: #d13b3b; font-weight: bold;"));
    layout->addWidget(warning);
    understood = new QCheckBox(QStringLiteral("我了解芯片上的所有数据都会丢失"), this);
    layout->addWidget(understood);
    bar = new QProgressBar(this); bar->setRange(0, 1000); bar->setTextVisible(false);
    stage = wrapped({}, this);
    layout->addWidget(bar); layout->addWidget(stage);
    auto *buttons = new QHBoxLayout();
    start = new QPushButton(QStringLiteral("开始刷写"), this);
    start->setStyleSheet(QStringLiteral("QPushButton { background: #642998; color: white; border: none; border-radius: 4px; padding: 4px 18px; }"
                                        "QPushButton:disabled { background: palette(button); color: palette(mid); }"));
    close = new QPushButton(QStringLiteral("关闭"), this);
    buttons->addStretch(1); buttons->addWidget(start); buttons->addWidget(close);
    layout->addLayout(buttons);

    connect(choose, &QPushButton::clicked, this, [this] {
        auto path = QFileDialog::getOpenFileName(this, QStringLiteral("选择固件"), image->text(), QStringLiteral("ESP32-S3 合并镜像 (*.bin);;所有文件 (*)"));
        if (!path.isEmpty()) image->setText(QDir::toNativeSeparators(path));
        refresh();
    });
    connect(understood, &QCheckBox::toggled, this, &FlashDialog::refresh);
    connect(start, &QPushButton::clicked, this, &FlashDialog::begin);
    connect(close, &QPushButton::clicked, this, &FlashDialog::reject);
    timer = new QTimer(this); connect(timer, &QTimer::timeout, this, &FlashDialog::tick); timer->start(200);
    scan();
    resize(560, sizeHint().height());
}
FlashDialog::~FlashDialog() {
    if (job) job->progress.cancel = true;
    if (worker.joinable()) worker.join();
}
void FlashDialog::scan() {
    auto found = esp::downloadPorts();
    auto current = ports->currentData().toString();
    QStringList paths;
    for (const auto &p : found) paths << qs(p.path);
    QStringList shown;
    for (int i = 0; i < ports->count(); ++i) shown << ports->itemData(i).toString();
    if (paths != shown) {
        ports->clear();
        for (const auto &p : found) ports->addItem(qs(p.label), qs(p.path));
        int keep = ports->findData(current); if (keep >= 0) ports->setCurrentIndex(keep);
    }
    portHint->setText(found.empty() ? QStringLiteral("未发现下载模式的设备。请按住 BOOT 插入 USB。")
                    : found.size() > 1 ? QStringLiteral("发现多个下载模式设备，请确认要刷写的那一个。") : QString());
    portHint->setVisible(!portHint->text().isEmpty());
    refresh();
}
void FlashDialog::refresh() {
    bool running = static_cast<bool>(job);
    choose->setEnabled(!running); ports->setEnabled(!running); understood->setEnabled(!running);
    start->setEnabled(!running && understood->isChecked() && ports->count() > 0 && !image->text().isEmpty());
    close->setText(running ? QStringLiteral("取消刷写") : QStringLiteral("关闭"));
}
void FlashDialog::begin() {
    if (job || !understood->isChecked() || ports->count() == 0) return;
    Bytes firmware;
    try { firmware = esp::readImage(std::filesystem::path(ws(image->text()))); }
    catch (const std::exception &e) { showError(this, QStringLiteral("检查固件"), e); return; }
    auto path = u8(ports->currentData().toString());
    job = std::make_shared<Job>();
    worker = std::thread([job = job, firmware = std::move(firmware), path] {
        try { auto link = esp::openSerial(path); esp::flash(*link, firmware, job->progress); }
        catch (const std::exception &e) { job->error = e.what(); }
        job->finished = true;
    });
    stage->setText(QStringLiteral("正在连接设备…"));
    refresh();
}
void FlashDialog::tick() {
    if (!job) { if (++ticks % 5 == 0) scan(); return; } // ports once a second while idle
    static const char *texts[] = {"", "正在连接设备…", "正在擦除整片 Flash，可能需要数十秒…", "正在写入固件…", "正在校验…", "正在重启设备…", ""};
    int s = job->progress.stage;
    bar->setValue(s >= esp::Progress::Verifying ? 1000 : s == esp::Progress::Writing ? job->progress.permille.load() : 0);
    if (s > 0 && s < esp::Progress::Done) stage->setText(qs(texts[s]));
    if (!job->finished) return;
    worker.join();
    auto done = std::move(job);
    if (done->error.empty()) {
        stage->setText(QStringLiteral("刷写完成并已校验。设备正在重启；若主窗口未出现新设备，请拔插一次 USB。"));
        understood->setChecked(false);
    } else {
        bar->setValue(0);
        stage->setText(safeLabel(done->error));
    }
    scan();
}
void FlashDialog::reject() {
    if (!job) { QDialog::reject(); return; }
    if (QMessageBox::question(this, QStringLiteral("取消刷写"),
            QStringLiteral("现在取消会让芯片处于不完整状态，需要重新刷写后才能使用。确定取消吗？")) != QMessageBox::Yes) return;
    job->progress.cancel = true;
    stage->setText(QStringLiteral("正在取消…"));
}
