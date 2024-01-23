//
// Created by sku on 22/01/2024.
//

#include "include/ui/FullListDialog.h"
#include <QDebug>


FullListDialog::FullListDialog(const set<string>& services, QWidget* parent)
        : QDialog(parent), listWidget(new QListWidget(this)),
          okButton(new QPushButton("OK", this)),
          cancelButton(new QPushButton("Cancel", this)) {

    for (const auto& service : services) {
        listWidget->addItem(QString::fromStdString(service));
    }

    QVBoxLayout* layout = new QVBoxLayout(this);
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    layout->addWidget(listWidget);
    layout->addLayout(buttonLayout);

    setLayout(layout);
    setWindowTitle("Select Application");
    setModal(true);
    resize(300, 400); // Adjust size as needed

    connect(okButton, SIGNAL(clicked()), this, SLOT(onOkClicked()));
    connect(cancelButton, SIGNAL(clicked()), this, SLOT(onCancelClicked()));
}

void FullListDialog::onOkClicked() {
    QListWidgetItem* selectedItem = listWidget->currentItem();
    if (selectedItem) {
        selectedService = selectedItem->text();
    }
    accept(); // Close the dialog with QDialog::Accepted
}

void FullListDialog::onCancelClicked() {
    reject(); // Close the dialog with QDialog::Rejected
}

QString FullListDialog::getSelectedService() const {
    return selectedService;
}

#include "include/ui/FullListDialog.moc"