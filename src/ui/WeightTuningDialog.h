#pragma once

/**
 * Dialog for tuning hybrid detection weights and ML confidence threshold.
 *
 * Provides three linked sliders for ML / Threat Intel / Heuristic weights
 * that maintain a sum-to-1.0 constraint: adjusting one slider proportionally
 * redistributes the remaining weight among the other two.
 *
 * Also provides a slider for the ML confidence threshold (the level below
 * which the hybrid engine consults TI and heuristic layers more aggressively).
 *
 * Changes are applied to both the HybridDetectionService (runtime) and
 * Configuration singleton (persisted for next launch).
 */

#include "app/HybridDetectionService.h"

#include <QDialog>
#include <QSlider>
#include <QLabel>
#include <QDoubleSpinBox>
#include <QPushButton>

namespace nids::ui {

/** Dialog for tuning hybrid detection weights and ML confidence threshold. */
class WeightTuningDialog : public QDialog {
    Q_OBJECT

public:
    /// @param hybridService  Non-owning pointer to the hybrid detection service.
    ///                       If nullptr, Apply is disabled (view-only mode).
    /// @param parent         Parent widget.
    explicit WeightTuningDialog(app::HybridDetectionService* hybridService,
                                QWidget* parent = nullptr);

private slots:
    void onMlSliderChanged(int value);
    void onTiSliderChanged(int value);
    void onHeuristicSliderChanged(int value);
    void onThresholdSliderChanged(int value);
    void applyWeights();
    void resetToDefaults();

private:
    void setupUi();
    void connectSignals() const;

    /// Update spin-box labels to reflect current slider positions.
    void syncLabelsFromSliders();

    /// Redistribute remaining weight proportionally across the other two sliders
    /// when one slider is moved.  Prevents infinite signal recursion via guard.
    void redistributeWeights(const QSlider* changed, QSlider* other1, QSlider* other2);

    app::HybridDetectionService* hybridService_ = nullptr;  // non-owning

    // Slider range: 0–100, representing 0.00–1.00 in increments of 0.01.
    QSlider* mlSlider_ = nullptr;
    QSlider* tiSlider_ = nullptr;
    QSlider* heuristicSlider_ = nullptr;
    QSlider* thresholdSlider_ = nullptr;

    QDoubleSpinBox* mlSpin_ = nullptr;
    QDoubleSpinBox* tiSpin_ = nullptr;
    QDoubleSpinBox* heuristicSpin_ = nullptr;
    QDoubleSpinBox* thresholdSpin_ = nullptr;

    QLabel* sumLabel_ = nullptr;

    QPushButton* applyButton_ = nullptr;
    QPushButton* resetButton_ = nullptr;
    QPushButton* closeButton_ = nullptr;

    bool adjusting_ = false;  // guard against recursive slider updates
};

} // namespace nids::ui
