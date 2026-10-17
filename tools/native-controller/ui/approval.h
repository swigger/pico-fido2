#pragma once
#include "relay_authenticator.h"
#include <QDialog>
#include <chrono>

class QLabel;
class QListWidget;
class QPushButton;

// One request shown to the operator, for both work modes. Relay: the decision
// applies only to this request; closing, expiry, session lock and remote
// cancellation all deny. Local (standalone device): approving signs this one
// request; closing leaves the device waiting for its own BOOT press, and the
// owner closes the dialog as soon as the device stops waiting.
class ApprovalDialog : public QDialog {
    Q_OBJECT
public:
    ApprovalDialog(const relay::Approval &approval, std::chrono::steady_clock::time_point deadline, bool local = false);
    relay::Decision decision() const { return result; }
    // Shows the dialog in front; when it closes, the application that was in
    // front before gets the focus back.
    void present();
private:
    relay::Approval approval;
    std::chrono::steady_clock::time_point deadline;
    bool local;
    relay::Decision result;
    QLabel *remaining = nullptr;
    QListWidget *list = nullptr;
    QPushButton *approve = nullptr;
    void tick();
    void allow();
};
// Called on the relay session thread. Shows the dialog on the GUI thread and
// blocks until a decision, polling operation.canceled() on the calling thread
// (it also services TLS keepalives and remote cancel frames).
relay::Decision approveOnGui(const relay::Approval &approval, const relay::Operation &operation);
