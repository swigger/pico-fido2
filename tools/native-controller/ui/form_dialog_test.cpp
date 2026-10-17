#include "widgets.h"
#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QFontMetrics>
#include <QLabel>
#include <QLineEdit>
#include <cstdio>
#include <stdexcept>

namespace {
void need(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
QLineEdit *edit(FormDialog &dialog, const QString &name) {
    for (auto *field : dialog.findChildren<QLineEdit *>()) if (field->accessibleName() == name) return field;
    throw std::runtime_error("field missing");
}
QVector<FormField> fields() {
    FormField operation; operation.title = "Operation"; operation.value = "existing";
    operation.choices = {{"existing", "Existing cloud"}, {"webdav", "New WebDAV"}};
    FormField identity; identity.title = "Namespace"; identity.limit = 32;
    identity.value = "0123456789abcdef0123456789abcdef";
    FormField password; password.title = "Password"; password.secret = true;
    password.visibleWhen = [](const QVector<QString> &values) { return values[0] == "webdav"; };
    FormField file; file.title = "Certificate"; file.file = true; file.visibleWhen = password.visibleWhen;
    return {operation, identity, password, file};
}
void growingInputs() {
    auto f = fields(); FormDialog dialog(nullptr, "Cloud form", "Choose and configure in one window.", f);
    dialog.show(); QApplication::processEvents();
    auto *identity = edit(dialog, "Namespace");
    need(identity->width() >= identity->fontMetrics().horizontalAdvance(identity->text()) + 20, "32-character identity is clipped at initial size");
    int before = identity->width(); dialog.resize(dialog.width() + 160, dialog.height()); QApplication::processEvents();
    need(identity->width() >= before + 120, "input does not grow with dialog");
    need(!edit(dialog, "Password")->isVisible(), "inactive configuration fields shown");
    auto *operation = dialog.findChild<QComboBox *>(); operation->setCurrentIndex(1); QApplication::processEvents();
    need(edit(dialog, "Password")->isVisible() && edit(dialog, "Certificate")->isVisible(), "operation change did not reveal needed fields");
    need(edit(dialog, "Certificate")->width() > 400, "file picker leaves a cramped path input");
    auto path = QStringLiteral("/Users/example/Certificates/coordinator-client.pem");
    edit(dialog, "Certificate")->setText(path);
    need(edit(dialog, "Certificate")->toolTip() == path && edit(dialog, "Password")->toolTip().isEmpty(), "full path tooltip missing or secret exposed");
    dialog.reject();
}
void validationAndCancel() {
    auto f = fields(); int validated = 0;
    FormDialog dialog(nullptr, "Cloud form", {}, f, [&](const QVector<QString> &values) {
        ++validated;
        return values[1] == QStringLiteral("invalid") ? QStringLiteral("Check namespace") : QString();
    });
    dialog.show(); QApplication::processEvents();
    edit(dialog, "Namespace")->setText("invalid"); dialog.accept(); QApplication::processEvents();
    need(dialog.isVisible() && validated == 1, "invalid input accepted or hidden required fields blocked validation");
    bool inlineError = false;
    for (auto *label : dialog.findChildren<QLabel *>()) inlineError |= label->isVisible() && label->text() == QStringLiteral("Check namespace");
    need(inlineError && QApplication::activeModalWidget() == &dialog, "validation did not stay in the current dialog");
    edit(dialog, "Namespace")->setText("0123456789abcdef0123456789abcdef");
    auto *operation = dialog.findChild<QComboBox *>(); operation->setCurrentIndex(1); QApplication::processEvents();
    dialog.accept(); need(dialog.isVisible() && validated == 1, "required fields for new provider ignored");
    edit(dialog, "Password")->setText("synthetic-secret"); edit(dialog, "Certificate")->setText("/fixture/client.pem");
    operation->setCurrentIndex(0); dialog.accept();
    need(dialog.result() == QDialog::Accepted && f[2].value.isEmpty() && f[3].value.isEmpty(), "inactive provider values were submitted");
    need(edit(dialog, "Password")->text().isEmpty(), "accepted dialog retained password widget text");
    f[0].value = "webdav"; f[2].value = "synthetic-initial-secret";
    FormDialog canceled(nullptr, "Cancel", {}, f); canceled.show(); QApplication::processEvents(); canceled.reject();
    need(f[2].value.isEmpty() && edit(canceled, "Password")->text().isEmpty(), "cancel retained secret input");
}
void rememberChoice() {
    FormField code; code.title = "Recovery code"; code.secret = true;
    FormField remember; remember.title = "Remember on this computer"; remember.checkbox = true;
    QVector<FormField> f{code, remember};
    FormDialog dialog(nullptr, "Unlock", {}, f);
    auto *check = dialog.findChild<QCheckBox *>(); need(check && !check->isChecked(), "remember must be opt-in");
    edit(dialog, code.title)->setText("00000000000000000000000000"); dialog.accept();
    need(dialog.result() == QDialog::Accepted && f[1].value == "0", "unchecked remember blocked input or became checked");
    FormDialog remembered(nullptr, "Unlock", {}, f);
    remembered.findChild<QCheckBox *>()->setChecked(true); remembered.accept();
    need(f[1].value == "1" && edit(remembered, code.title)->text().isEmpty(), "remember choice lost or secret widget retained");
    f[1].value = "0";
    FormDialog canceled(nullptr, "Unlock", {}, f); canceled.findChild<QCheckBox *>()->setChecked(true); canceled.reject();
    need(f[0].value.isEmpty() && f[1].value == "0", "cancel submitted remember choice or retained secret");
}
}
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    try { growingInputs(); validationAndCancel(); rememberChoice(); std::puts("PASS: readable/resizable inputs, conditional requirements, inline validation, remember choice and canceled secrets"); }
    catch (const std::exception &error) { std::fprintf(stderr, "FAIL: %s\n", error.what()); return 1; }
    return 0;
}
