#pragma once

#include "core/services/PacketFilter.h"
#include "core/services/ServiceRegistry.h"

#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QRegularExpressionValidator>

#include <vector>
#include <string>

namespace nids::ui {

class FilterPanel : public QWidget {
    Q_OBJECT

public:
    explicit FilterPanel(const nids::core::ServiceRegistry& registry,
                         QWidget* parent = nullptr);

    void setInterfaces(const std::vector<std::string>& interfaces);
    [[nodiscard]] nids::core::PacketFilter gatherFilter() const;
    [[nodiscard]] std::string selectedInterface() const;

    void setInputsReadOnly(bool readOnly);

signals:
    void interfaceChanged(const QString& interface);
    void startStopClicked();

public slots:
    void setButtonText(const QString& text);

private slots:
    void validateInputs();
    void onApplicationChanged(int index);
    void updateApplicationFromPort();

private:
    void setupLayout();
    void populateProtocols();
    void populateApplications();

    const nids::core::ServiceRegistry& serviceRegistry_;

    QComboBox* networkCardCombo_ = nullptr;
    QComboBox* protocolCombo_ = nullptr;
    QComboBox* applicationCombo_ = nullptr;
    QLineEdit* sourceIpEdit_ = nullptr;
    QLineEdit* sourcePortEdit_ = nullptr;
    QLineEdit* destIpEdit_ = nullptr;
    QLineEdit* destPortEdit_ = nullptr;
    QLineEdit* customFilterEdit_ = nullptr;
    QPushButton* startStopButton_ = nullptr;

    QRegularExpression ipRegex_;
    QRegularExpression portRegex_;
    QRegularExpressionValidator* ipValidator_ = nullptr;
    QRegularExpressionValidator* portValidator_ = nullptr;

    QString lastCustomService_;
    QString lastAddedService_;
};

} // namespace nids::ui
