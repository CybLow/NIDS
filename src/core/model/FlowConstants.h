#pragma once

/// Flow-level constants shared across all layers.
///
/// Centralizes the feature count so that core/, infra/, and app/
/// layers all reference the same named constant.

namespace nids::core {

/// Number of flow features produced by the flow feature extractor.
/// Matches the CIC-IDS2017 / LSNM2024 77-feature specification.
inline constexpr int kFlowFeatureCount = 77;

} // namespace nids::core
