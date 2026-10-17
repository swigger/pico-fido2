#pragma once
// Small shared Qt helpers: string conversion, safe display, errors and input forms.
#include "platform.h"
#include <QDialog>
#include <QString>
#include <QVector>
#include <QPair>
#include <exception>
#include <functional>

class QWidget;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QLabel;

QString qs(const std::string &utf8Text);
QString qs(const std::wstring &text);
QString qs(const char *utf8Text);
std::wstring ws(const QString &text);
std::string u8(const QString &text);
// Device/website supplied text: control and bidi-override characters replaced.
QString safeLabel(const std::string &utf8Text);
void showError(QWidget *parent, const QString &title, const std::exception &error);
QString hexFingerprint(const unsigned char *id16);

struct FormField {
    QString title, value;
    bool secret = false, file = false, required = true, readOnly = false;
    int limit = 512;
    QVector<QPair<QString, QString>> choices; // value, label
    bool editableChoice = false;
    bool checkbox = false; // value is "1" when checked, "0" otherwise
    // Hidden fields are neither required nor submitted. Values stay in the
    // dialog while switching choices, and are cleared when it closes.
    std::function<bool(const QVector<QString> &)> visibleWhen;
};
using FormValidator = std::function<QString(const QVector<QString> &)>;
// A modal form; on acceptance each field's value is updated. Secret inputs are
// cleared from their widgets when the dialog closes.
class FormDialog : public QDialog {
    Q_OBJECT
public:
    FormDialog(QWidget *parent, const QString &title, const QString &explanation, QVector<FormField> &fields,
               FormValidator validate = {});
    ~FormDialog() override;
    static bool ask(QWidget *parent, const QString &title, const QString &explanation, QVector<FormField> &fields,
                    FormValidator validate = {});
    void accept() override;
    void reject() override;
private:
    QVector<FormField> &fields;
    QVector<QLineEdit *> edits;
    QVector<QComboBox *> combos;
    QVector<QCheckBox *> checks;
    QVector<QWidget *> labels, inputs;
    QLabel *error = nullptr;
    FormValidator validate;
    QVector<QString> values() const;
    void updateVisibility();
    void showValidation(const QString &message, int field = -1);
    void clear();
};
// Single secret or text prompt. confirm adds a repeat field; minimum counts characters.
bool askText(QWidget *parent, const QString &title, const QString &prompt, std::wstring &value,
             bool secret, bool confirm = false, int minimum = 1, int maximum = 256, const QString &hint = {});
