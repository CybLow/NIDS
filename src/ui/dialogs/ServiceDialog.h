#pragma once

#include <QDialog>
#include <QListWidget>
#include <QPushButton>

#include <set>
#include <string>

namespace nids::ui {

class ServiceDialog : public QDialog {
    Q_OBJECT

public:
    explicit ServiceDialog(const std::set<std::string>& services,
                           QWidget* parent = nullptr);

    [[nodiscard]] QString getSelectedService() const;

private slots:
    void onOkClicked();
    void onCancelClicked();

private:
    QListWidget* listWidget_;
    QPushButton* okButton_;
    QPushButton* cancelButton_;
    QString selectedService_;
};

} // namespace nids::ui
