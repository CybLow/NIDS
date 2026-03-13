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

/** Widget panel providing capture filter controls (interface, protocol, IP, port). */
class FilterPanel : public QWidget {
    Q_OBJECT

public:
    /** Construct with a service registry for protocol/application lookups. */
    explicit FilterPanel(const nids::core::ServiceRegistry& registry,
                         QWidget* parent = nullptr);

    /** Populate the network interface combo box. */
    void setInterfaces(const std::vector<std::string>& interfaces);
    /** Build a PacketFilter from the current UI field values. */
    [[nodiscard]] nids::core::PacketFilter gatherFilter() const;
    /** Return the currently selected network interface name. */
    [[nodiscard]] std::string selectedInterface() const;

    /** Enable or disable editing of the filter input fields. */
    void setInputsReadOnly(bool readOnly);

signals:
    /** Emitted when the user selects a different network interface. */
    void interfaceChanged(const QString& interface);
    /** Emitted when the start/stop button is clicked. */
    void startStopClicked();

public slots:
    /** Set the label text of the start/stop button. */
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
