#include "approval.h"
#include "cli.h"
#include "controller_instance.h"
#include "main_window.h"
#include "relay_server.h"
#include "relay_settings.h"
#include "session_monitor.h"
#include "widgets.h"
#include <QApplication>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif

namespace {
// --serve: a small status window; the TLS service runs on its own thread and
// every request opens a separate approval dialog.
int serveWindow(relay::Server &server, const std::string &address, uint16_t port) {
    QDialog window; window.setWindowTitle(QStringLiteral("Pico FIDO · 安全端服务"));
    auto *layout = new QVBoxLayout(&window);
    auto *label = new QLabel(QStringLiteral("正在启动安全端…"), &window); label->setWordWrap(true); label->setTextFormat(Qt::PlainText);
    auto *stop = new QPushButton(QStringLiteral("停止服务"), &window);
    layout->addWidget(label); layout->addWidget(stop, 0, Qt::AlignRight);
    std::atomic_bool stopping{false}, finished{false}, failed{false};
    std::mutex mutex; QString status = label->text();
    auto update = [&](const QString &text) { std::lock_guard<std::mutex> guard(mutex); status = text; };
    std::thread worker([&] {
        try {
            server.run(address, port, [&] { return stopping.load(); },
                [&](uint16_t actual) { update(QStringLiteral("正在监听 %1:%2\n收到有效设备的请求时，将单独询问是否批准。").arg(qs(address)).arg(actual)); },
                [&](const std::string &error) { update(QStringLiteral("服务继续运行。上次连接未完成：\n") + safeLabel(error)); });
        } catch (const std::exception &e) { failed = true; update(QStringLiteral("服务无法启动：\n") + safeLabel(e.what())); }
        finished = true;
    });
    QObject::connect(stop, &QPushButton::clicked, &window, [&] { stopping = true; stop->setEnabled(false); update(QStringLiteral("正在取消当前请求并停止服务…")); });
    QTimer timer; QObject::connect(&timer, &QTimer::timeout, &window, [&] {
        { std::lock_guard<std::mutex> guard(mutex); label->setText(status); }
        if (finished && (stopping || failed)) stop->setText(QStringLiteral("关闭")), stop->setEnabled(true);
        if (finished && stopping) window.accept();
    });
    QObject::connect(&window, &QDialog::rejected, &window, [&] { stopping = true; });
    timer.start(100);
    window.resize(560, 180);
    window.exec();
    stopping = true; worker.join();
    return failed ? 1 : 0;
}
#ifdef _WIN32
void attachConsole() {
    // A GUI-subsystem program can still serve scripts from a terminal.
    auto out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == nullptr || out == INVALID_HANDLE_VALUE) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        FILE *f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout); freopen_s(&f, "CONOUT$", "w", stderr);
    }
}
#endif
}

int main(int argc, char **argv) {
    std::vector<std::string> args; std::string serial;
    bool valid = true;
    try { args = commandLine(argc, argv); valid = splitDevice(args, serial); } catch (...) { valid = false; }
    unsigned instanceWaitMs = 0;
#ifdef _WIN32
    // Only the successful UAC handoff waits for the previous GUI to finish.
    // It still has to acquire the same lock; this flag never bypasses it.
    if (valid && args.size() == 2 && args[0] == "--accounts" && args[1] == "--restart-elevated" && platform::isElevated()) {
        args.pop_back(); instanceWaitMs = 30000;
    }
#endif
    if (!valid || !isGuiCommand(args)) {
#ifdef _WIN32
        attachConsole();
#endif
        try {
            if (!valid) throw std::runtime_error("--device requires one 16-digit hexadecimal serial");
            auto instance = acquireControllerInstance(args);
            return runCli(args, serial);
        } catch (const std::exception &e) { std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1; }
    }
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QApplication::setAttribute(Qt::AA_DisableWindowContextHelpButton);
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
    platform::FileLock instance; // Outlives QApplication and every GUI worker.
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Pico FIDO Controller"));
    QApplication::setOrganizationName(QStringLiteral("PicoFido2Remote"));
    QApplication::setQuitOnLastWindowClosed(true);
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/app.png")));
    try {
        instance = acquireControllerInstance(args, {}, instanceWaitMs);
        (void)SessionMonitor::instance();
        if (!args.empty() && args[0] == "--serve") {
#ifdef _WIN32
            attachConsole();
#endif
            std::string address = args.size() == 3 ? args[1] : "0.0.0.0";
            uint16_t port = args.size() == 3 ? parsePort(args[2]) : 8443;
            auto controller = Key::load(); if (!controller) throw std::runtime_error("请先创建控制端密钥，并通过 USB 完成设备配对");
            relay::Storage storage; auto &vault = openStorage(storage);
            relay::Server server(vault, *controller, [](const std::string &device) { return relayDeviceKey(device); },
                approveOnGui);
            return serveWindow(server, address, port);
        }
        int tab = args.empty() ? MainWindow::DeviceTab : args[0] == "--accounts" ? MainWindow::AccountsTab : MainWindow::ServiceTab;
        MainWindow window(tab, serial);
        window.show();
        return app.exec();
    } catch (const std::exception &e) {
        QMessageBox::critical(nullptr, QStringLiteral("Pico FIDO"), safeLabel(e.what()));
        return 1;
    }
}
