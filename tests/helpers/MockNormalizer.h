#pragma once

/// Shared mock for IFeatureNormalizer.
///
/// Consolidates MockFeatureNormalizer, MockNormalizer, MockNormalizerLDP,
/// and MockNormalizerWorker into a single reusable header.

#include <gmock/gmock.h>

#include "core/services/IFeatureNormalizer.h"

#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace nids::testing {

class MockNormalizer : public core::IFeatureNormalizer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadMetadata,
                (const std::string&), (override));
    MOCK_METHOD(std::vector<float>, normalize, (std::span<const float>),
                (const, override));
    MOCK_METHOD(bool, isLoaded, (), (const, noexcept, override));
    MOCK_METHOD(std::size_t, featureCount, (), (const, noexcept, override));

    /// Create a pass-through normalizer that returns features unchanged.
    static std::unique_ptr<MockNormalizer> createPassThrough() {
        auto mock = std::make_unique<MockNormalizer>();
        ON_CALL(*mock, normalize(::testing::_))
            .WillByDefault([](std::span<const float> f) {
                return std::vector<float>(f.begin(), f.end());
            });
        return mock;
    }
};

} // namespace nids::testing
