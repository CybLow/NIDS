#include "ui/dialogs/ServiceDialog.h"

#include <QHBoxLayout>
#include <QVBoxLayout>

namespace nids::ui {

ServiceDialog::ServiceDialog(const std::set<std::string, std::less<>> &services,
                             QWidget *parent)
    : QDialog(parent), listWidget_(new QListWidget(this)) // NOSONAR
      ,
      okButton_(new QPushButton("OK", this)) // NOSONAR
      ,
      cancelButton_(new QPushButton("Cancel", this)) { // NOSONAR

  for (const auto &service : services) {
    listWidget_->addItem(QString::fromStdString(service));
  }

  auto *layout = new QVBoxLayout(this);   // NOSONAR
  auto *buttonLayout = new QHBoxLayout(); // NOSONAR
  buttonLayout->addWidget(okButton_);
  buttonLayout->addWidget(cancelButton_);
  layout->addWidget(listWidget_);
  layout->addLayout(buttonLayout);

  setWindowTitle("Select Application");
  setModal(true);
  resize(300, 400);

  connect(okButton_, &QPushButton::clicked, this, &ServiceDialog::onOkClicked);
  connect(cancelButton_, &QPushButton::clicked, this,
          &ServiceDialog::onCancelClicked);
}

void ServiceDialog::onOkClicked() {
  if (const auto *item = listWidget_->currentItem()) {
    selectedService_ = item->text();
  }
  accept();
}

void ServiceDialog::onCancelClicked() { reject(); }

const QString &ServiceDialog::getSelectedService() const {
  return selectedService_;
}

} // namespace nids::ui
