#pragma once

#include <QDialog>
#include <QListWidget>
#include <QPushButton>

#include <set>
#include <string>

namespace nids::ui {

/** Modal dialog for selecting a network service from a list. */
class ServiceDialog : public QDialog {
    Q_OBJECT

public:
    /** Construct with the set of available service names. */
    explicit ServiceDialog(const std::set<std::string>& services,
                           QWidget* parent = nullptr);

    /** Return the service name selected by the user, or empty if cancelled. */
    [[nodiscard]] const QString& getSelectedService() const;

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
