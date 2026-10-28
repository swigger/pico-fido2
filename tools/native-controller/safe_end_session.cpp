#include "safe_end_session.h"
#include "credentials.h"
#include "relay_server.h"
#include "relay_settings.h"
#include "relay_backup.h"
#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace relay {
namespace {
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
std::string label(const std::string &value) {
    try { return utf8(ctap::Value::string(value).label()); }
    catch (...) { return "无法显示该内容"; }
}
}
SafeEndSession::SafeEndSession(std::filesystem::path directory, std::function<void()> callback, const CloudLaunch &options)
    : dir(std::move(directory)), notify(std::move(callback)), cloudLaunch(options) {
    working = true;
    pending = [this] { readState(); publish("选择打开凭证库，或先初始化与恢复。每次中转请求仍需单独批准。"); };
    worker = std::thread([this] { run(); });
}
SafeEndSession::~SafeEndSession() { close(); }
void SafeEndSession::close() {
    { std::lock_guard<std::mutex> guard(mutex); closing = true; cancel = true; }
    wake.notify_all();
    if (worker.joinable()) worker.join();
}
CloudLaunch SafeEndSession::launch() const {
    auto out = cloudLaunch;
    out.canceled = [this, parent = out.canceled] { return cancel.load() || closing.load() || (parent && parent()); }; return out;
}
SessionSnapshot SafeEndSession::snapshot() const { std::lock_guard<std::mutex> guard(mutex); return state; }
void SafeEndSession::publish(const std::string &message, bool rows) {
    std::vector<Account> data; if (rows && opened) data = opened->accounts();
    { std::lock_guard<std::mutex> guard(mutex);
      state.status = message; state.unlocked = opened != nullptr;
      if (rows || !opened) state.rows = std::move(data);
      ++state.version; }
    if (notify) notify();
}
void SafeEndSession::publishRows(bool refresh) {
    if (!opened) return;
    auto data = refresh ? opened->accounts() : opened->displayAccounts();
    { std::lock_guard<std::mutex> guard(mutex); state.rows = std::move(data); ++state.version; }
    if (notify) notify();
}
void SafeEndSession::readState() {
    auto temporary = owner ? nullptr : std::make_unique<Storage>(dir, launch()); auto &current = owner ? *owner : *temporary;
    auto choice = current.choice(); auto local = dir / ("credentials-v1" + platform::protectedExtension()); auto marker = local; marker += ".lock";
    bool initialized = choice.kind != StorageKind::Unbound &&
        (choice.kind != StorageKind::Local || std::filesystem::exists(local) || std::filesystem::exists(marker));
    auto ns = choice.nameSpace;
    if (choice.kind == StorageKind::Local && initialized) ns = opened ? opened->namespaceId() : current.localNamespace();
    auto profiles = CloudStorage::configuredNamespaces(dir / "cloud");
    std::lock_guard<std::mutex> guard(mutex);
    if (ns.empty() && !initialized) {
        if (std::find(profiles.begin(), profiles.end(), state.nameSpace) != profiles.end()) ns = state.nameSpace;
    }
    state.kind = choice.kind; state.nameSpace = ns; state.initialized = initialized;
    state.cloudProfiles = std::move(profiles); ++state.version;
}
void SafeEndSession::release() { opened = nullptr; owner.reset(); }
Storage &SafeEndSession::storage() { if (!owner) owner = std::make_unique<Storage>(dir, launch()); return *owner; }
void SafeEndSession::resetStorage() { release(); }
void SafeEndSession::acquire(const std::wstring &password) { opened = &storage().open(password); readState(); }
void SafeEndSession::acquireRemembered() {
    if (storage().choice().kind != StorageKind::Cloud) { acquire({}); return; }
    struct Secret { std::wstring code; std::string answer; ~Secret() { wipe(code); wipe(answer); } } secret;
    std::string hint;
    try { secret.code = storage().rememberedCloudCode(); }
    catch (const std::exception &) { hint = "无法读取已记住的恢复码，请手动输入。"; }
    bool remembered = !secret.code.empty(), remember = false;
    for (;;) {
        need(!canceled(), "操作已取消");
        if (secret.code.empty()) {
            EnrollmentQuestion q; q.kind = CloudRecoveryCodeQuestion; q.secret = true;
            q.message = hint;
            publish(hint.empty() ? "等待输入云端库恢复码…" : hint);
            secret.answer = ask(q);
            need(secret.answer.size() == 27 && (secret.answer[0] == '0' || secret.answer[0] == '1'), "恢复码格式不正确");
            remember = secret.answer[0] == '1';
            secret.code.assign(secret.answer.begin() + 1, secret.answer.end()); wipe(secret.answer);
            auto normalized = backup::recoveryCode(secret.code); wipe(secret.code); secret.code.swap(normalized); wipe(normalized);
        }
        need(!canceled(), "操作已取消");
        publish(remembered ? "正在使用已记住的恢复码打开云端库…" : "正在打开云端凭证库…");
        try { acquire(secret.code); }
        catch (const backup::PasswordError &) {
            storage().forgetCloudCode(); wipe(secret.code);
            hint = remembered ? "已记住的恢复码无法解密当前云端库，记录已清除，请重新输入。"
                              : "恢复码不正确或云端数据已损坏，请重新输入。";
            remembered = false; remember = false; continue;
        }
        need(!canceled(), "操作已取消");
        if (!remembered) {
            if (remember) storage().rememberCloudCode(secret.code);
            else storage().forgetCloudCode();
        }
        return;
    }
}
void SafeEndSession::exportBackup(const std::filesystem::path &path, const std::wstring &password) {
    need(opened != nullptr, "请先打开凭证库");
    publish("正在加密并写入备份…"); opened->exportBackup(path, password);
    publish("加密备份已创建。请将密码与备份分开保管。");
    if (storage().choice().kind == StorageKind::Cloud) {
        EnrollmentQuestion q; q.kind = DetachCloudAfterBackupQuestion; q.value = path.u8string();
        q.message = "解除后会删除当前库在本机保存的恢复码、云授权和协调服务器连接配置，并关闭此库。\n"
                    "云端凭证库、其他客户端、其他库配置和本机设备配对均保留。"
                    "您可以初始化新的本机库、从备份恢复，或重新连接云端库。\n"
                    "这不会迁移云端数据，也不会清除此软件的全部本机数据。请妥善保管备份及密码。";
        auto answer = ask(q);
        if (answer != "detach") { publish("加密备份已创建，云端绑定已保留。"); return; }
        need(!canceled(), "操作已取消，云端绑定已保留");
        publish("正在校验备份并解除本机云端绑定…");
        // Storage may destroy the vault even if finishing the durable removal
        // later fails. Do not retain a dangling UI/session pointer on that path.
        opened = nullptr;
        storage().detachCloudAfterBackup(path, password, [this] { return canceled(); });
        readState(); publish("加密备份已保存，云端绑定已解除。现在可以初始化本机库、从备份恢复或连接云端库。", true);
        return;
    }
    EnrollmentQuestion q; q.kind = ClearLocalAfterBackupQuestion; q.value = path.u8string();
    q.message = "清空后将删除本机库中的全部凭证、私钥、计数器和中转 PIN 状态，"
                "可以再从同一份或其他加密备份恢复。\n"
                "请确认已妥善保存备份文件及密码；只有备份文件和正确密码才能恢复此库。\n"
                "本机授权密钥、设备配对和网络设置会保留。";
    auto answer = ask(q);
    if (answer != "clear") { publish("加密备份已创建，本机库已保留。"); return; }
    need(!canceled(), "操作已取消，本机库未清空");
    publish("正在校验备份并清空本机库…");
    storage().clearLocalAfterBackup(path, password, [this] { return canceled(); }); opened = nullptr;
    readState(); publish("加密备份已保存，本机库已清空。现在可以从备份恢复或初始化新库。", true);
}
void SafeEndSession::setNamespace(const std::string &nameSpace) {
    readState(); // A successful profile save immediately enables the matching cloud actions.
    std::lock_guard<std::mutex> guard(mutex); state.nameSpace = nameSpace; ++state.version;
}
bool SafeEndSession::submit(std::function<void()> action) {
    { std::lock_guard<std::mutex> guard(mutex);
      if (closing || lockRequested || (working && !maintenance)) return false;
      if (!working) { working = true; cancel = false; }
      pending = std::move(action); }
    wake.notify_all();
    if (notify) notify();
    return true;
}
void SafeEndSession::requestLock() {
    { std::lock_guard<std::mutex> guard(mutex); lockRequested = true; cancel = true; working = true; }
    wake.notify_all();
}
std::string SafeEndSession::ask(const EnrollmentQuestion &value) {
    auto request = std::make_shared<Question>(); request->question = value;
    std::unique_lock<std::mutex> guard(mutex); need(!question && !cancel && !closing, "操作已取消");
    question = request; guard.unlock(); if (notify) notify(); guard.lock();
    while (!request->complete && !cancel && !closing) wake.wait_for(guard, std::chrono::milliseconds(100));
    question.reset(); need(request->complete && !request->failed && !cancel && !closing, "操作已取消或无法完成确认");
    return std::move(request->answer);
}
bool SafeEndSession::pendingQuestion(EnrollmentQuestion &out) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!question || question->dispatched || question->complete || cancel || closing) return false;
    question->dispatched = true; out = question->question; return true;
}
void SafeEndSession::answer(bool accepted, const std::string &value) {
    { std::lock_guard<std::mutex> guard(mutex);
      if (!question || question->complete) return;
      question->answer = value; question->failed = !accepted; question->complete = true; }
    wake.notify_all();
}
void SafeEndSession::run() {
    for (;;) {
        std::function<void()> action; bool locking = false, health = false;
        { std::unique_lock<std::mutex> guard(mutex);
          wake.wait_for(guard, std::chrono::seconds(1), [&] { return closing || pending || lockRequested; });
          if (closing) { pending = {}; break; }
          if (lockRequested) { pending = {}; lockRequested = false; locking = true; }
          else if (pending) action = std::exchange(pending, nullptr); // a moved-from std::function need not be empty
          else if (opened) { action = [this] { (void)owner->open(); }; health = true; } // local selector/fault check; no idle cloud lease
          else continue;
          maintenance = health; working = true; }
        if (locking) action = [this] { release(); readState(); publish("凭证库已锁定。"); };
        try { action(); if (cancel) { release(); publish("已停止并锁定。解锁后可继续管理。"); } }
        catch (const std::exception &e) { release(); try { readState(); } catch (...) {} publish("操作未完成：" + label(e.what())); }
        action = {};
        { std::lock_guard<std::mutex> guard(mutex); if (!lockRequested) working = false; maintenance = false; }
        if (notify) notify();
    }
    release(); finished = true; working = false;
    if (notify) notify();
}
void serveRelay(SafeEndSession &s, const std::string &address, uint16_t port, Authenticator::Approve approve,
                const std::function<void(uint16_t)> &ready) {
    need(s.vault() != nullptr, "请先打开凭证库");
    auto controller = Key::load(); need(controller != nullptr, "请先在主窗口生成本机密钥，并与硬件配对");
    // Keep a UI snapshot between operations. An explicit refresh reacquires
    // the cloud transaction and also sees writes from other clients.
    s.publishRows(false);
    auto listed = s.vault()->revision();
    Server server(*s.vault(), *controller, [](const std::string &serial) { return relayDeviceKey(serial); },
        std::move(approve));
    server.run(address, port, [&] { return s.canceled(); },
        [&](uint16_t actual) {
            s.publish("服务运行于 " + address + ":" + std::to_string(actual) + "；每个请求都需要单独批准。");
            if (ready) ready(actual);
        },
        [&](const std::string &) { s.publish("上次连接未完成；服务继续等待已配置设备的请求。"); },
        [&] {
            (void)s.storage().open();
            auto now = s.vault()->revision();
            bool refresh = s.takeRowsRequest();
            if (refresh || now != listed) { s.publishRows(refresh); listed = s.vault()->revision(); }
        });
    s.release(); s.publish("服务已停止，凭证库已锁定。");
}
}
