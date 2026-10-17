#pragma once
#include "esp_flasher.h"
#include <QDialog>
#include <memory>
#include <thread>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QTimer;

// "刷写新设备": writes the firmware image shipped with the controller (or one the
// user picks) to an ESP32-S3 in ROM download mode. The whole chip is erased
// without backup, so starting requires ticking an explicit acknowledgement.
// The write runs on a worker thread; closing the dialog cancels it.
class FlashDialog : public QDialog {
    Q_OBJECT
public:
    explicit FlashDialog(QWidget *parent);
    ~FlashDialog() override;
    // The image bundled with the application, or empty.
    static QString bundledImage();
    void reject() override;
private:
    struct Job {
        esp::Progress progress;
        std::atomic_bool finished{false};
        std::string error;
    };
    std::shared_ptr<Job> job;
    std::thread worker;
    QLineEdit *image = nullptr;
    QComboBox *ports = nullptr;
    QLabel *portHint = nullptr, *stage = nullptr;
    QCheckBox *understood = nullptr;
    QProgressBar *bar = nullptr;
    QPushButton *choose = nullptr, *start = nullptr, *close = nullptr;
    QTimer *timer = nullptr;
    int ticks = 0;
    void scan();
    void begin();
    void tick();
    void refresh();
};
