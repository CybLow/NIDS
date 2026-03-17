#include "ui/WeightTuningDialog.h"
#include "core/services/Configuration.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QVBoxLayout>

namespace nids::ui {

namespace {
constexpr int kSliderMin = 0;
constexpr int kSliderMax = 100;
constexpr int kSliderTickInterval = 10;
constexpr double kSliderScale = 100.0;
constexpr double kSpinStep = 0.01;
constexpr int kSpinDecimals = 2;
constexpr int kDialogMinWidth = 420;

/// Convert a slider integer position (0–100) to a float weight (0.0–1.0).
[[nodiscard]] float sliderToWeight(int sliderValue) {
    return static_cast<float>(sliderValue) / static_cast<float>(kSliderScale);
}

// Default weight values (must match HybridDetectionService::Weights defaults)
constexpr float kDefaultMl = 0.5f;
constexpr float kDefaultTi = 0.3f;
constexpr float kDefaultHeuristic = 0.2f;
constexpr float kDefaultThreshold = 0.7f;
} // namespace

WeightTuningDialog::WeightTuningDialog(
    app::HybridDetectionService *hybridService, QWidget *parent)
    : QDialog(parent), hybridService_(hybridService) {
  setWindowTitle("Hybrid Detection Weights");
  setMinimumWidth(kDialogMinWidth);
  setupUi();
  connectSignals();
}

void WeightTuningDialog::setupUi() {
  const auto &config = core::Configuration::instance();

  // -- Weight sliders --
  auto *weightsGroup =
      new QGroupBox("Detection Weights (must sum to 1.0)", this); // NOSONAR
  auto *weightsLayout = new QFormLayout(weightsGroup);            // NOSONAR

  auto makeWeightRow = [this](const QString &label, QSlider *&slider,
                              QDoubleSpinBox *&spin, float initialValue) {
    slider = new QSlider(Qt::Horizontal, this); // NOSONAR
    slider->setRange(kSliderMin, kSliderMax);
    slider->setTickInterval(kSliderTickInterval);
    slider->setTickPosition(QSlider::TicksBelow);
    slider->setValue(static_cast<int>(initialValue * kSliderScale));

    spin = new QDoubleSpinBox(this); // NOSONAR
    spin->setRange(0.0, 1.0);
    spin->setSingleStep(kSpinStep);
    spin->setDecimals(kSpinDecimals);
    spin->setValue(static_cast<double>(initialValue));
    spin->setReadOnly(true);
    spin->setButtonSymbols(QAbstractSpinBox::NoButtons);

    auto *row = new QHBoxLayout(); // NOSONAR
    row->addWidget(slider, 1);
    row->addWidget(spin);

    return std::make_pair(label, row);
  };

  auto [mlLabel, mlRow] =
      makeWeightRow("ML Weight", mlSlider_, mlSpin_, config.weightMl());
  auto [tiLabel, tiRow] = makeWeightRow("Threat Intel Weight", tiSlider_,
                                        tiSpin_, config.weightThreatIntel());
  auto [heuLabel, heuRow] =
      makeWeightRow("Heuristic Weight", heuristicSlider_, heuristicSpin_,
                    config.weightHeuristic());

  weightsLayout->addRow(mlLabel, mlRow);
  weightsLayout->addRow(tiLabel, tiRow);
  weightsLayout->addRow(heuLabel, heuRow);

  sumLabel_ = new QLabel(this); // NOSONAR
  syncLabelsFromSliders();
  weightsLayout->addRow("Sum:", sumLabel_);

  // -- Threshold slider --
  auto *thresholdGroup =
      new QGroupBox("ML Confidence Threshold", this);      // NOSONAR
  auto *thresholdLayout = new QFormLayout(thresholdGroup); // NOSONAR

  thresholdSlider_ = new QSlider(Qt::Horizontal, this); // NOSONAR
  thresholdSlider_->setRange(kSliderMin, kSliderMax);
  thresholdSlider_->setTickInterval(kSliderTickInterval);
  thresholdSlider_->setTickPosition(QSlider::TicksBelow);
  thresholdSlider_->setValue(
      static_cast<int>(config.mlConfidenceThreshold() * kSliderScale));

  thresholdSpin_ = new QDoubleSpinBox(this); // NOSONAR
  thresholdSpin_->setRange(0.0, 1.0);
  thresholdSpin_->setSingleStep(kSpinStep);
  thresholdSpin_->setDecimals(kSpinDecimals);
  thresholdSpin_->setValue(static_cast<double>(config.mlConfidenceThreshold()));
  thresholdSpin_->setReadOnly(true);
  thresholdSpin_->setButtonSymbols(QAbstractSpinBox::NoButtons);

  auto *thresholdRow = new QHBoxLayout(); // NOSONAR
  thresholdRow->addWidget(thresholdSlider_, 1);
  thresholdRow->addWidget(thresholdSpin_);

  thresholdLayout->addRow("Threshold", thresholdRow);

  auto *thresholdNote = new QLabel( // NOSONAR
      "Below this confidence level, TI and heuristic signals are\n"
      "consulted more aggressively for the final verdict.",
      this);
  thresholdNote->setWordWrap(true);
  thresholdNote->setStyleSheet("color: gray; font-size: 11px;");
  thresholdLayout->addRow(thresholdNote);

  // -- Buttons --
  applyButton_ = new QPushButton("Apply", this);             // NOSONAR
  resetButton_ = new QPushButton("Reset to Defaults", this); // NOSONAR
  closeButton_ = new QPushButton("Close", this);             // NOSONAR

  if (!hybridService_) {
    applyButton_->setEnabled(false);
    applyButton_->setToolTip("No hybrid detection service available");
  }

  auto *buttonLayout = new QHBoxLayout(); // NOSONAR
  buttonLayout->addStretch();
  buttonLayout->addWidget(resetButton_);
  buttonLayout->addWidget(applyButton_);
  buttonLayout->addWidget(closeButton_);

  // -- Main layout --
  auto *mainLayout = new QVBoxLayout(this); // NOSONAR
  mainLayout->addWidget(weightsGroup);
  mainLayout->addWidget(thresholdGroup);
  mainLayout->addLayout(buttonLayout);
}

void WeightTuningDialog::connectSignals() const {
  connect(mlSlider_, &QSlider::valueChanged, this,
          &WeightTuningDialog::onMlSliderChanged);
  connect(tiSlider_, &QSlider::valueChanged, this,
          &WeightTuningDialog::onTiSliderChanged);
  connect(heuristicSlider_, &QSlider::valueChanged, this,
          &WeightTuningDialog::onHeuristicSliderChanged);
  connect(thresholdSlider_, &QSlider::valueChanged, this,
          &WeightTuningDialog::onThresholdSliderChanged);

  connect(applyButton_, &QPushButton::clicked, this,
          &WeightTuningDialog::applyWeights);
  connect(resetButton_, &QPushButton::clicked, this,
          &WeightTuningDialog::resetToDefaults);
  connect(closeButton_, &QPushButton::clicked, this, &QDialog::close);
}

void WeightTuningDialog::onMlSliderChanged(int /*value*/) {
  redistributeWeights(mlSlider_, tiSlider_, heuristicSlider_);
  syncLabelsFromSliders();
}

void WeightTuningDialog::onTiSliderChanged(int /*value*/) {
  redistributeWeights(tiSlider_, mlSlider_, heuristicSlider_);
  syncLabelsFromSliders();
}

void WeightTuningDialog::onHeuristicSliderChanged(int /*value*/) {
  redistributeWeights(heuristicSlider_, mlSlider_, tiSlider_);
  syncLabelsFromSliders();
}

void WeightTuningDialog::onThresholdSliderChanged(int value) {
  thresholdSpin_->setValue(static_cast<double>(value) / kSliderScale);
}

void WeightTuningDialog::redistributeWeights(const QSlider *changed,
                                             QSlider *other1, QSlider *other2) {
  if (adjusting_)
    return;
  adjusting_ = true;

  int changedVal = changed->value();
  int remaining = kSliderMax - changedVal;

  int other1Val = other1->value();
  int other2Val = other2->value();

  if (int otherSum = other1Val + other2Val; otherSum > 0) {
    // Proportional redistribution: keep the ratio between the other two
    int new1 = (other1Val * remaining) / otherSum;
    int new2 = remaining - new1; // ensure exact sum to avoid rounding drift
    other1->setValue(new1);
    other2->setValue(new2);
  } else {
    // Both others are zero — split evenly
    other1->setValue(remaining / 2);
    other2->setValue(remaining - remaining / 2);
  }

  adjusting_ = false;
}

void WeightTuningDialog::syncLabelsFromSliders() {
  double ml = static_cast<double>(mlSlider_->value()) / kSliderScale;
  double ti = static_cast<double>(tiSlider_->value()) / kSliderScale;
  double heu = static_cast<double>(heuristicSlider_->value()) / kSliderScale;

  mlSpin_->setValue(ml);
  tiSpin_->setValue(ti);
  heuristicSpin_->setValue(heu);

  double sum = ml + ti + heu;
  sumLabel_->setText(QString::number(sum, 'f', 2));

  // Visual feedback: green if sum == 1.0, red otherwise
  constexpr double kEpsilon = 0.015; // allow small rounding tolerance
  if (std::abs(sum - 1.0) < kEpsilon) {
    sumLabel_->setStyleSheet("color: green; font-weight: bold;");
  } else {
    sumLabel_->setStyleSheet("color: red; font-weight: bold;");
  }
}

void WeightTuningDialog::applyWeights() {
  auto ml = sliderToWeight(mlSlider_->value());
  auto ti = sliderToWeight(tiSlider_->value());
  auto heu = sliderToWeight(heuristicSlider_->value());
  auto threshold = sliderToWeight(thresholdSlider_->value());

  // Apply to runtime service
  if (hybridService_) {
    hybridService_->setWeights({.ml = ml, .threatIntel = ti, .heuristic = heu});
    hybridService_->setConfidenceThreshold(threshold);
  }

  // Persist to configuration singleton
  auto &config = core::Configuration::instance();
  config.setWeightMl(ml);
  config.setWeightThreatIntel(ti);
  config.setWeightHeuristic(heu);
  config.setMlConfidenceThreshold(threshold);
}

void WeightTuningDialog::resetToDefaults() {
  adjusting_ = true;
  mlSlider_->setValue(static_cast<int>(kDefaultMl * kSliderScale));
  tiSlider_->setValue(static_cast<int>(kDefaultTi * kSliderScale));
  heuristicSlider_->setValue(
      static_cast<int>(kDefaultHeuristic * kSliderScale));
  thresholdSlider_->setValue(
      static_cast<int>(kDefaultThreshold * kSliderScale));
  adjusting_ = false;

  syncLabelsFromSliders();
}

} // namespace nids::ui
