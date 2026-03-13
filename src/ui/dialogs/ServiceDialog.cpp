#include "ui/dialogs/ServiceDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>

namespace nids::ui {

ServiceDialog::ServiceDialog(const std::set<std::string>& services, QWidget* parent)
    : QDialog(parent)
    , listWidget_(new QListWidget(this))
    , okButton_(new QPushButton("OK", this))
    , cancelButton_(new QPushButton("Cancel", this)) {

    for (const auto& service : services) {
        listWidget_->addItem(QString::fromStdString(service));
    }

    auto* layout = new QVBoxLayout(this);
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(okButton_);
    buttonLayout->addWidget(cancelButton_);
    layout->addWidget(listWidget_);
    layout->addLayout(buttonLayout);

    setWindowTitle("Select Application");
    setModal(true);
    resize(300, 400);

    connect(okButton_, &QPushButton::clicked, this, &ServiceDialog::onOkClicked);
    connect(cancelButton_, &QPushButton::clicked, this, &ServiceDialog::onCancelClicked);
}

void ServiceDialog::onOkClicked() {
    auto* item = listWidget_->currentItem();
    if (item) {
        selectedService_ = item->text();
    }
    accept();
}

void ServiceDialog::onCancelClicked() {
    reject();
}

const QString& ServiceDialog::getSelectedService() const {
    return selectedService_;
}

} // namespace nids::ui
