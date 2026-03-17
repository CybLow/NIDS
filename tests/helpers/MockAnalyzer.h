#pragma once

/// Shared mock for IPacketAnalyzer.
///
/// Consolidates MockAnalyzer, MockAnalyzerLDP, MockAnalyzerWorker,
/// and MockAnalyzerWithConfidence into a single reusable header.

#include <gmock/gmock.h>

#include "core/model/PredictionResult.h"
#include "core/services/IPacketAnalyzer.h"

#include <expected>
#include <span>
#include <string>
#include <vector>

namespace nids::testing {

/// Basic analyzer mock (predict only).
class MockAnalyzer : public core::IPacketAnalyzer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadModel,
                (const std::string&), (override));
    MOCK_METHOD(core::AttackType, predict, (std::span<const float>), (override));
};

/// Analyzer mock with confidence support (predict + predictWithConfidence).
/// Does NOT mock predictBatch — the base class default delegates to
/// predictWithConfidence, which is the correct behavior for tests that
/// set up expectations on predictWithConfidence.
class MockAnalyzerWithConfidence : public core::IPacketAnalyzer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadModel,
                (const std::string&), (override));
    MOCK_METHOD(core::AttackType, predict, (std::span<const float>), (override));
    MOCK_METHOD(core::PredictionResult, predictWithConfidence,
                (std::span<const float>), (override));
};

/// Full analyzer mock (predict + predictWithConfidence + predictBatch).
/// Use when tests need explicit control over predictBatch behavior.
class MockAnalyzerFull : public core::IPacketAnalyzer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadModel,
                (const std::string&), (override));
    MOCK_METHOD(core::AttackType, predict, (std::span<const float>), (override));
    MOCK_METHOD(core::PredictionResult, predictWithConfidence,
                (std::span<const float>), (override));
    MOCK_METHOD(std::vector<core::PredictionResult>, predictBatch,
                (std::span<const float>, std::size_t), (override));
};

} // namespace nids::testing
