#include "widgets.h"
#include "credentials.h"
#include <algorithm>
#include <QComboBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QVBoxLayout>

QString qs(const std::string &text) { return QString::fromUtf8(text.data(), static_cast<int>(text.size())); }
QString qs(const char *text) { return QString::fromUtf8(text); }
QString qs(const std::wstring &text) { return qs(utf8(text)); }
std::string u8(const QString &text) { auto b = text.toUtf8(); std::string out(b.constData(), static_cast<size_t>(b.size())); b.fill('\0'); return out; }
std::wstring ws(const QString &text) { auto s = u8(text); auto out = widen(s); wipe(s); return out; }
QString safeLabel(const std::string &text) {
    try { return qs(ctap::Value::string(text).label()); }
    catch (...) { return QStringLiteral("无法显示该内容"); }
}
void showError(QWidget *parent, const QString &title, const std::exception &error) {
    QMessageBox::warning(parent, title, safeLabel(error.what()));
}
QString hexFingerprint(const unsigned char *id) {
    auto s = qs(hex(id, 16));
    return s.mid(0, 8) + ' ' + s.mid(8, 8) + ' ' + s.mid(16, 8) + ' ' + s.mid(24, 8);
}

FormDialog::FormDialog(QWidget *parent, const QString &title, const QString &explanation, QVector<FormField> &f, FormValidator validator)
    : QDialog(parent), fields(f), validate(std::move(validator)) {
    setWindowTitle(title);
    setModal(true);
    auto *layout = new QVBoxLayout(this);
    if (!explanation.isEmpty()) {
        if (explanation.count('\n') > 3 || explanation.size() > 240) {
            auto *text = new QPlainTextEdit(explanation, this);
            text->setReadOnly(true); text->setMinimumHeight(150);
            layout->addWidget(text);
        } else {
            auto *label = new QLabel(explanation, this);
            label->setWordWrap(true); label->setTextFormat(Qt::PlainText);
            layout->addWidget(label);
        }
    }
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true); scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto *body = new QWidget(scroll);
    auto *form = new QFormLayout(body);
    form->setContentsMargins(0, 4, 12, 4);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setFormAlignment(Qt::AlignTop);
    form->setVerticalSpacing(10);
    for (int i = 0; i < fields.size(); ++i) {
        auto &field = fields[i];
        QLineEdit *edit = nullptr; QComboBox *combo = nullptr; QCheckBox *check = nullptr;
        if (field.checkbox) {
            check = new QCheckBox(field.title, this); check->setAccessibleName(field.title);
            check->setChecked(field.value == QStringLiteral("1")); check->setEnabled(!field.readOnly);
            inputs.push_back(check);
        } else if (!field.choices.isEmpty()) {
            combo = new QComboBox(this);
            combo->setAccessibleName(field.title);
            combo->setEditable(field.editableChoice);
            combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            combo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
            combo->setMinimumContentsLength(24);
            for (const auto &choice : field.choices) combo->addItem(choice.second, choice.first);
            int index = combo->findData(field.value);
            if (index >= 0) combo->setCurrentIndex(index);
            else if (field.editableChoice) combo->setEditText(field.value);
            if (combo->lineEdit()) {
                combo->lineEdit()->setMaxLength(field.limit);
                if (field.secret) combo->lineEdit()->setEchoMode(QLineEdit::Password);
            }
            inputs.push_back(combo);
        } else {
            edit = new QLineEdit(field.value, this);
            edit->setAccessibleName(field.title);
            edit->setMaxLength(field.limit);
            edit->setReadOnly(field.readOnly);
            edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            edit->setCursorPosition(0);
            if (field.secret) edit->setEchoMode(QLineEdit::Password);
            else {
                edit->setToolTip(field.value);
                connect(edit, &QLineEdit::textChanged, edit, &QLineEdit::setToolTip);
            }
            if (field.file) {
                auto *rowWidget = new QWidget(this);
                auto *row = new QHBoxLayout(rowWidget); row->setContentsMargins(0, 0, 0, 0);
                auto *browse = new QPushButton(QStringLiteral("浏览…"), this);
                connect(browse, &QPushButton::clicked, this, [this, edit] {
                    auto path = QFileDialog::getOpenFileName(this, QStringLiteral("选择文件"), {},
                        QStringLiteral("证书与私钥 (*.pem *.crt *.key *.cer);;所有文件 (*)"));
                    if (!path.isEmpty()) { edit->setText(path); edit->setCursorPosition(0); }
                });
                row->addWidget(edit, 1); row->addWidget(browse);
                inputs.push_back(rowWidget);
            } else inputs.push_back(edit);
        }
        auto *label = new QLabel(check ? QString() : field.title, body); label->setTextFormat(Qt::PlainText);
        label->setBuddy(combo ? static_cast<QWidget *>(combo) : check ? static_cast<QWidget *>(check) : edit);
        labels.push_back(label); form->addRow(label, inputs.back());
        edits.push_back(edit); combos.push_back(combo); checks.push_back(check);
    }
    scroll->setWidget(body); layout->addWidget(scroll, 1);
    error = new QLabel(this); error->setWordWrap(true); error->setTextFormat(Qt::PlainText);
    error->setStyleSheet(QStringLiteral("color: #b42318;")); error->hide(); layout->addWidget(error);
    auto *buttons = new QDialogButtonBox(this);
    auto *cancel = buttons->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
    buttons->addButton(QStringLiteral("继续"), QDialogButtonBox::AcceptRole);
    cancel->setDefault(true); // Accidental Enter never confirms.
    connect(buttons, &QDialogButtonBox::accepted, this, &FormDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &FormDialog::reject);
    layout->addWidget(buttons);
    for (auto *combo : combos) if (combo)
        connect(combo, &QComboBox::currentTextChanged, this, [this] { updateVisibility(); });
    for (auto *check : checks) if (check)
        connect(check, &QCheckBox::toggled, this, [this] { updateVisibility(); });
    for (auto *edit : edits) if (edit)
        connect(edit, &QLineEdit::textChanged, this, [this] { if (error) error->hide(); });
    updateVisibility();
    auto *screen = QGuiApplication::screenAt(parent ? parent->mapToGlobal(parent->rect().center()) : pos());
    if (!screen) screen = QGuiApplication::primaryScreen();
    auto available = screen ? screen->availableGeometry().size() : QSize(1024, 768);
    const int width = std::min(fields.size() > 5 ? 880 : 760, std::max(320, available.width() - 48));
    setMinimumWidth(std::min(640, width)); setSizeGripEnabled(true);
    body->adjustSize();
    int height = std::min(std::max(230, body->sizeHint().height() + 150), std::max(200, available.height() - 96));
    resize(width, height);
    if (fields.empty()) scroll->hide();
    for (int i = 0; i < edits.size(); ++i)
        if (edits[i] && !edits[i]->isReadOnly() && !inputs[i]->isHidden()) { edits[i]->setFocus(); break; }
}
FormDialog::~FormDialog() { clear(); }
void FormDialog::clear() {
    for (auto *e : edits) if (e) { e->clear(); }
    for (auto *c : combos) if (c && c->lineEdit()) c->lineEdit()->clear();
}
QVector<QString> FormDialog::values() const {
    QVector<QString> result;
    for (int i = 0; i < fields.size(); ++i) {
        const auto &field = fields[i]; QString value;
        if (auto *c = combos[i]) {
            int index = field.editableChoice ? c->findText(c->currentText()) : c->currentIndex();
            if (index >= 0) value = c->itemData(index).toString();
            else if (field.editableChoice) value = c->currentText();
        } else if (auto *check = checks[i]) value = check->isChecked() ? QStringLiteral("1") : QStringLiteral("0");
        else value = edits[i]->text();
        result.push_back(value);
    }
    return result;
}
void FormDialog::updateVisibility() {
    auto current = values();
    for (int i = 0; i < fields.size(); ++i) {
        bool visible = !fields[i].visibleWhen || fields[i].visibleWhen(current);
        labels[i]->setVisible(visible); inputs[i]->setVisible(visible);
    }
    if (error) error->hide();
    if (isVisible() && !inputs.empty()) {
        auto *body = inputs.front()->parentWidget();
        body->layout()->invalidate(); body->layout()->activate();
        auto *screen = QGuiApplication::screenAt(mapToGlobal(rect().center()));
        if (!screen) screen = QGuiApplication::primaryScreen();
        int maximum = screen ? screen->availableGeometry().height() - 96 : 672;
        int wanted = std::min(body->sizeHint().height() + 150, std::max(200, maximum));
        if (wanted > height()) resize(width(), wanted);
    }
}
void FormDialog::showValidation(const QString &message, int field) {
    error->setText(message); error->show();
    if (field >= 0) {
        if (edits[field]) edits[field]->setFocus();
        else if (combos[field]) combos[field]->setFocus();
        else checks[field]->setFocus();
    }
}
void FormDialog::accept() {
    auto current = values();
    for (int i = 0; i < fields.size(); ++i) {
        const auto &field = fields[i];
        if (field.visibleWhen && !field.visibleWhen(current)) continue;
        if ((field.required && current[i].isEmpty()) || current[i].size() > field.limit) {
            showValidation(QStringLiteral("请检查“%1”：内容不能为空或超过 %2 个字符。").arg(field.title).arg(field.limit), i); return;
        }
    }
    if (validate) {
        auto message = validate(current);
        if (!message.isEmpty()) { showValidation(message); return; }
    }
    for (int i = 0; i < fields.size(); ++i) {
        fields[i].value = (!fields[i].visibleWhen || fields[i].visibleWhen(current)) ? current[i] : QString();
    }
    clear();
    QDialog::accept();
}
void FormDialog::reject() { clear(); for (auto &field : fields) if (field.secret) { field.value.fill(QChar(0)); field.value.clear(); } QDialog::reject(); }
bool FormDialog::ask(QWidget *parent, const QString &title, const QString &explanation, QVector<FormField> &fields, FormValidator validate) {
    FormDialog dialog(parent, title, explanation, fields, std::move(validate));
    return dialog.exec() == QDialog::Accepted;
}

bool askText(QWidget *parent, const QString &title, const QString &prompt, std::wstring &value, bool secret, bool confirm,
             int minimum, int maximum, const QString &hint) {
    QVector<FormField> fields;
    FormField first; first.title = prompt; first.secret = secret; first.limit = maximum; first.required = minimum > 0;
    if (!secret) first.value = qs(value);
    fields.push_back(first);
    if (confirm) { FormField repeat = first; repeat.title = QStringLiteral("再次输入"); repeat.value.clear(); fields.push_back(repeat); }
    if (!FormDialog::ask(parent, title, hint, fields, [=](const QVector<QString> &values) {
        if (confirm && values[0] != values[1]) return QStringLiteral("两次输入不一致，请重新核对。");
        if (values[0].size() < minimum) return QStringLiteral("至少需要 %1 个字符。").arg(minimum);
        return QString();
    })) { for (auto &f : fields) f.value.fill(QChar(0)); return false; }
    value = ws(fields[0].value);
    for (auto &f : fields) f.value.fill(QChar(0));
    return true;
}
