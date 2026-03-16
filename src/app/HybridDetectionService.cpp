#include "app/HybridDetectionService.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>

namespace nids::app {

HybridDetectionService::HybridDetectionService(
    nids::core::IThreatIntelligence *threatIntel,
    nids::core::IRuleEngine *ruleEngine)
    : threatIntel_(threatIntel), ruleEngine_(ruleEngine) {}

void HybridDetectionService::setWeights(const Weights &weights) noexcept {
  weights_ = weights;
}

void HybridDetectionService::setConfidenceThreshold(float threshold) noexcept {
  confidenceThreshold_ = threshold;
}

void HybridDetectionService::populateThreatIntel(
    nids::core::DetectionResult &result, const std::string &srcIp,
    const std::string &dstIp) const {
  if (threatIntel_ == nullptr) {
    return;
  }
  if (auto srcLookup = threatIntel_->lookup(srcIp); srcLookup.matched) {
    result.threatIntelMatches.push_back(
        {.ip = srcIp, .feedName = srcLookup.feedName, .isSource = true});
  }
  if (auto dstLookup = threatIntel_->lookup(dstIp); dstLookup.matched) {
    result.threatIntelMatches.push_back(
        {.ip = dstIp, .feedName = dstLookup.feedName, .isSource = false});
  }
}

nids::core::DetectionResult HybridDetectionService::evaluate(
    const nids::core::PredictionResult &mlResult, const std::string &srcIp,
    const std::string &dstIp, const nids::core::FlowInfo &flowInfo) const {

  nids::core::DetectionResult result;
  result.mlResult = mlResult;

  // -- Layer 2: Threat Intelligence --
  populateThreatIntel(result, srcIp, dstIp);

  // -- Layer 3: Heuristic Rules --
  if (ruleEngine_ != nullptr) {
    result.ruleMatches = ruleEngine_->evaluate(flowInfo);
  }

  // -- Combine signals --
  bool hasTi = result.hasThreatIntelMatch();
  bool hasRules = result.hasRuleMatch();
  float maxSev = result.maxRuleSeverity();

  result.combinedScore = computeCombinedScore(mlResult, hasTi, maxSev);
  result.finalVerdict = determineVerdict(mlResult, hasTi, hasRules, maxSev);
  result.detectionSource =
      determineSource(mlResult.isAttack(), hasTi, hasRules);

  if (hasTi && !mlResult.isAttack()) {
    spdlog::info("TI override: ML classified flow as {} (conf={:.3f}) but "
                 "IP matched threat intel feed",
                 nids::core::attackTypeToString(mlResult.classification),
                 mlResult.confidence);
  }

  return result;
}

nids::core::DetectionResult
HybridDetectionService::evaluate(const nids::core::PredictionResult &mlResult,
                                 const std::string &srcIp,
                                 const std::string &dstIp) const {

  nids::core::DetectionResult result;
  result.mlResult = mlResult;

  // -- Layer 2: Threat Intelligence (no heuristic rules) --
  populateThreatIntel(result, srcIp, dstIp);

  bool hasTi = result.hasThreatIntelMatch();
  result.combinedScore = computeCombinedScore(mlResult, hasTi, 0.0f);
  result.finalVerdict = determineVerdict(mlResult, hasTi, false, 0.0f);
  result.detectionSource = determineSource(mlResult.isAttack(), hasTi, false);

  return result;
}

float HybridDetectionService::computeCombinedScore(
    const nids::core::PredictionResult &mlResult, bool hasTiMatch,
    float maxRuleSeverity) const noexcept {

  // ML score: probability of being malicious
  float mlScore = 0.0f;
  if (mlResult.isAttack()) {
    mlScore = mlResult.confidence;
  } else if (mlResult.classification == nids::core::AttackType::Benign) {
    // Invert: benign with high confidence = low threat
    mlScore = 1.0f - mlResult.confidence;
  }
  // Unknown: mlScore stays 0.0

  float tiScore = hasTiMatch ? 1.0f : 0.0f;
  float ruleScore = maxRuleSeverity;

  float combined = weights_.ml * mlScore + weights_.threatIntel * tiScore +
                   weights_.heuristic * ruleScore;

  return std::clamp(combined, 0.0f, 1.0f);
}

nids::core::DetectionSource
HybridDetectionService::determineSource(bool mlIsAttack, bool hasTiMatch,
                                        bool hasRuleMatch) noexcept {

  // Encode the three booleans as a 3-bit index: (ml << 2 | ti << 1 | rule)
  // This replaces 6 chained if-statements with a single table lookup.
  using enum nids::core::DetectionSource;
  static constexpr std::array<nids::core::DetectionSource, 8> kSourceTable = {{
      /* 0b000: !ml, !ti, !rule */ None,
      /* 0b001: !ml, !ti,  rule */ HeuristicRule,
      /* 0b010: !ml,  ti, !rule */ ThreatIntel,
      /* 0b011: !ml,  ti,  rule */ ThreatIntel,
      /* 0b100:  ml, !ti, !rule */ MlOnly,
      /* 0b101:  ml, !ti,  rule */ MlPlusHeuristic,
      /* 0b110:  ml,  ti, !rule */ MlPlusThreatIntel,
      /* 0b111:  ml,  ti,  rule */ Ensemble,
  }};

  const auto index = (static_cast<unsigned>(mlIsAttack) << 2) |
                     (static_cast<unsigned>(hasTiMatch) << 1) |
                     static_cast<unsigned>(hasRuleMatch);
  return kSourceTable[index];
}

nids::core::AttackType HybridDetectionService::verdictForBenign(
    const nids::core::PredictionResult &mlResult, bool hasTiMatch,
    bool hasRuleMatch, float maxRuleSeverity) const noexcept {

  using enum nids::core::AttackType;

  // TI match overrides benign verdict -- this is the key escalation
  if (hasTiMatch) {
    return Unknown;
  }

  // High-severity heuristic rule + low ML confidence = escalate
  if (hasRuleMatch && maxRuleSeverity >= 0.7f &&
      !mlResult.isHighConfidence(confidenceThreshold_)) {
    return Unknown;
  }

  return Benign;
}

nids::core::AttackType HybridDetectionService::determineVerdict(
    const nids::core::PredictionResult &mlResult, bool hasTiMatch,
    bool hasRuleMatch, float maxRuleSeverity) const noexcept {

  using enum nids::core::AttackType;

  // ML says attack (any confidence) -- trust the classification
  if (mlResult.isAttack()) {
    return mlResult.classification;
  }

  // ML says benign -- apply escalation logic
  if (mlResult.classification == Benign) {
    return verdictForBenign(mlResult, hasTiMatch, hasRuleMatch,
                            maxRuleSeverity);
  }

  // Unknown ML result -- defer to TI
  return hasTiMatch ? Unknown : mlResult.classification;
}

} // namespace nids::app
