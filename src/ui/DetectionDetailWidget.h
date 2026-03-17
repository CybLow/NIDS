#pragma once

/**
 * Detail panel showing full hybrid detection breakdown for a selected flow.
 *
 * Displays ML verdict with confidence, probability distribution across all
 * attack types, threat intelligence matches, heuristic rule matches, and
 * the combined score breakdown. Read-only; populated via setResult().
 */

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <QWidget>
#include <QLabel>
#include <QTableWidget>
#include <QGroupBox>
#include <QVBoxLayout>

namespace nids::ui {

/** Detail panel showing full hybrid detection breakdown for a selected flow. */
class DetectionDetailWidget : public QWidget {
    Q_OBJECT

public:
    /** Construct an empty detection detail panel. */
    explicit DetectionDetailWidget(QWidget* parent = nullptr);

    /// Populate the panel with a detection result and optional flow metadata.
    void setResult(const core::DetectionResult& result,
                   const core::FlowInfo* metadata = nullptr);

    /// Clear all fields to blank state.
    void clearResult();

private:
    void setupUi();
    void populateFlowSection(const core::FlowInfo* metadata);
    void populateVerdictSection(const core::DetectionResult& result);
    void populateMlSection(const core::DetectionResult& result);
    void populateTiSection(const core::DetectionResult& result);
    void populateRulesSection(const core::DetectionResult& result);

    // -- Flow metadata section --
    QGroupBox* flowGroup_ = nullptr;
    QLabel* flowSrcLabel_ = nullptr;
    QLabel* flowDstLabel_ = nullptr;
    QLabel* flowProtocolLabel_ = nullptr;
    QLabel* flowDurationLabel_ = nullptr;
    QLabel* flowPacketsLabel_ = nullptr;

    // -- Combined verdict section --
    QGroupBox* verdictGroup_ = nullptr;
    QLabel* verdictLabel_ = nullptr;
    QLabel* combinedScoreLabel_ = nullptr;
    QLabel* detectionSourceLabel_ = nullptr;

    // -- ML section --
    QGroupBox* mlGroup_ = nullptr;
    QLabel* mlClassLabel_ = nullptr;
    QLabel* mlConfidenceLabel_ = nullptr;
    QTableWidget* probabilityTable_ = nullptr;

    // -- Threat intelligence section --
    QGroupBox* tiGroup_ = nullptr;
    QTableWidget* tiTable_ = nullptr;

    // -- Heuristic rules section --
    QGroupBox* rulesGroup_ = nullptr;
    QTableWidget* rulesTable_ = nullptr;
};

} // namespace nids::ui
