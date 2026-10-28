#include "safe_end_panel.h"
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>
#include <fstream>
#include <stdexcept>

namespace {
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
void wait(const std::function<bool()> &done) {
    QElapsedTimer timer; timer.start();
    while (!done()) {
        need(timer.elapsed() < 8000, "panel state did not settle");
        QApplication::processEvents(); sleepMs(5);
    }
}
QPushButton *button(SafeEndPanel &panel, const QString &label) {
    for (auto *b : panel.findChildren<QPushButton *>()) if (b->text() == label) return b;
    throw std::runtime_error("missing panel button");
}
void write(const std::filesystem::path &path, const std::string &text) {
    std::ofstream out(path, std::ios::binary); out << text; out.close();
    need(!out.fail(), "cannot prepare helper fixture");
}
void cloudConfiguration(bool initialized) {
    QTemporaryDir temporary(QDir::tempPath() + "/pf2-cloud-test-XXXXXX");
    need(temporary.isValid(), "cannot create test directory");
    auto dir = std::filesystem::u8path(temporary.path().toUtf8().constData());
    std::string ns = "0123456789abcdef0123456789abcdef", other = "fedcba9876543210fedcba9876543210";
    if (initialized) { relay::Storage storage(dir); storage.initializeLocal(); ns = storage.localNamespace(); }
    auto panel = std::make_unique<SafeEndPanel>(nullptr, dir);
    auto idle = [&] { wait([&] { return button(*panel, QStringLiteral("配置云存储"))->isEnabled(); }); };
    auto refresh = [&] {
        button(*panel, QStringLiteral("刷新"))->click();
        QApplication::processEvents(); // Render the queued submit notification before checking for idle.
        idle();
    };
    auto actions = [&](bool configured, bool matching) {
        need(button(*panel, QStringLiteral("建立云端库"))->isEnabled() == (!initialized && configured), "new cloud configuration gate incorrect");
        need(button(*panel, QStringLiteral("连接已有库"))->isEnabled() == (!initialized && configured), "existing cloud configuration gate incorrect");
        need(button(*panel, QStringLiteral("迁移到云端"))->isEnabled() == (initialized && matching), "migration did not require its own cloud profile");
        need(button(*panel, QStringLiteral("初始化本机库"))->isEnabled() == !initialized, "cloud configuration changed local initialization availability");
        need(button(*panel, QStringLiteral("从备份恢复"))->isEnabled() == !initialized, "cloud configuration changed local restore availability");
    };
    idle(); actions(false, false);
    std::filesystem::create_directory(dir / "cloud");
    auto profile = dir / "cloud" / (ns + platform::protectedExtension());
    write(std::filesystem::path(profile.string() + ".lock"), "PF2CLCK1" + ns);
    write(dir / "cloud" / ("invalid-namespace" + platform::protectedExtension()), "synthetic-profile");
    write(profile, ""); refresh(); actions(false, false); // A marker or empty/invalid file is not a saved profile.
    auto unrelated = dir / "cloud" / (other + platform::protectedExtension());
    write(unrelated, "synthetic-profile"); refresh(); actions(true, false);
    std::filesystem::remove(unrelated);
    write(profile, "synthetic-profile"); refresh(); actions(true, true);
    panel->shutdown(); panel.reset();
    panel = std::make_unique<SafeEndPanel>(nullptr, dir); idle(); actions(true, true);
    if (!initialized) {
        bool configuredChoices = false;
        QTimer::singleShot(0, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog) return;
            auto combos = dialog->findChildren<QComboBox *>();
            configuredChoices = combos.size() == 1 && !combos[0]->isEditable() && combos[0]->count() == 1 &&
                combos[0]->currentText() == QString::fromStdString(ns);
            dialog->reject();
        });
        button(*panel, QStringLiteral("连接已有库"))->click();
        need(configuredChoices, "cloud form allowed an unconfigured namespace");
    }
    std::filesystem::remove(profile); refresh(); actions(false, false);
    panel->shutdown();
}
void detachedLocal(const std::filesystem::path &helper, bool migrated, bool restart) {
    QTemporaryDir temporary(QDir::tempPath() + "/pf2-cloud-test-XXXXXX");
    need(temporary.isValid(), "cannot create test directory");
    auto dir = std::filesystem::u8path(temporary.path().toUtf8().constData());
    auto target = dir / "selected", backup = dir / "backup.pf2bak";
    relay::CloudLaunch launch; launch.helper = helper; launch.profile = dir / "profile";
    launch.timeout = std::chrono::seconds(3);
    write(launch.profile, "normal");
    const std::wstring password = L"synthetic-panel-backup-password";
    std::string cloudId = "0123456789abcdef0123456789abcdef";
    {
        relay::Storage storage(target, launch);
        if (migrated) { storage.initializeLocal(); cloudId = storage.localNamespace(); }
        auto marker = launch.profile; marker += ".lock"; write(marker, "PF2CLCK1" + cloudId);
        if (migrated) storage.migrateCloud(password); else storage.initializeCloud(cloudId, password);
    }
    auto panel = std::make_unique<SafeEndPanel>(nullptr, target);
    wait([&] { return button(*panel, QStringLiteral("打开凭证库"))->isEnabled(); });
    need(!button(*panel, QStringLiteral("初始化本机库"))->isEnabled(), "bound cloud allowed local initialization");
    {
        relay::Storage storage(target, launch);
        storage.open(password).exportBackup(backup, password);
        storage.detachCloudAfterBackup(backup, password);
    }
    if (restart) {
        panel->shutdown(); panel.reset();
        panel = std::make_unique<SafeEndPanel>(nullptr, target);
    } else button(*panel, QStringLiteral("刷新"))->click();
    auto *initialize = button(*panel, QStringLiteral("初始化本机库"));
    wait([&] { return initialize->isEnabled(); });
    need(button(*panel, QStringLiteral("从备份恢复"))->isEnabled(), "detached cloud disabled local restore");
    need(!button(*panel, QStringLiteral("打开凭证库"))->isEnabled(), "detached cloud exposed an old vault");
    initialize->click();
    wait([&] { return button(*panel, QStringLiteral("创建加密备份"))->isEnabled(); });
    need(!initialize->isEnabled(), "initialized vault can be overwritten");
    panel->shutdown(); panel.reset();
    relay::Storage reopened(target, launch);
    need(reopened.choice().kind == relay::StorageKind::Local && reopened.open().namespaceId() != cloudId && reopened.open().accounts().empty(),
         "panel did not persist a fresh local vault");
}
}
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("PicoFidoControllerTests");
    QCoreApplication::setApplicationName("DetachedLocal");
    QTemporaryDir settings;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settings.path());
    try {
        need(argc == 2, "expected synthetic cloud helper path");
        auto helper = std::filesystem::absolute(std::filesystem::u8path(argv[1]));
        for (bool initialized : {false, true}) {
            std::fprintf(stderr, "CASE cloud configuration (local initialized=%d)\n", initialized);
            cloudConfiguration(initialized);
        }
        for (bool migrated : {false, true}) for (bool restart : {false, true}) {
            std::fprintf(stderr, "CASE detached local (migrated=%d, restart=%d)\n", migrated, restart);
            detachedLocal(helper, migrated, restart);
        }
        std::puts("PASS: cloud configuration gates and local actions after detach, refresh and restart");
    } catch (const std::exception &error) { std::fprintf(stderr, "FAIL: %s\n", error.what()); return 1; }
    return 0;
}
