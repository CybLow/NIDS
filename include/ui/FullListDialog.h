#ifndef FULLLISTDIALOG_H
#define FULLLISTDIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QVBoxLayout>
#include <set>
#include <string>
#include <QPushButton>

using namespace std;

class FullListDialog : public QDialog {
Q_OBJECT
public:
    explicit FullListDialog(const std::set<std::string>& services, QWidget* parent = nullptr);
    QString getSelectedService() const;

private slots:
    void onOkClicked();
    void onCancelClicked();

private:
    QListWidget* listWidget;
    QPushButton* okButton;
    QPushButton* cancelButton;
    QString selectedService;
};

#endif // FULLLISTDIALOG_H
