#pragma once

/// Shared mock for IFlowExtractor.
///
/// Consolidates MockFlowExtractor, MockExtractor, and MockFlowExtractorLDP
/// into a single reusable header.

#include <gmock/gmock.h>

#include "core/services/IFlowExtractor.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace nids::testing {

/// Basic flow extractor mock: MOCK_METHOD for extractFeatures/flowMetadata,
/// no-op stubs for live-mode methods.
class MockFlowExtractor : public core::IFlowExtractor {
public:
    MockFlowExtractor() {
        ON_CALL(*this, flowMetadata())
            .WillByDefault(::testing::ReturnRef(emptyMetadata_));
    }

    void setFlowCompletionCallback(FlowCompletionCallback /*cb*/) override {}
    void processPacket(const std::uint8_t* /*data*/, std::size_t /*length*/,
                       std::int64_t /*timestampUs*/) override {}
    void finalizeAllFlows() override {}
    void reset() override {}
    void setFlowTimeout(std::int64_t /*timeoutUs*/) override {}
    void setMaxFlowDuration(std::int64_t /*durationUs*/) override {}

    MOCK_METHOD(std::vector<std::vector<float>>, extractFeatures,
                (const std::string&), (override));
    MOCK_METHOD((const std::vector<core::FlowInfo>&), flowMetadata, (),
                (const, noexcept, override));

    std::vector<core::FlowInfo> emptyMetadata_;
};

/// Full flow extractor mock: all methods are MOCK_METHOD (for live-mode tests).
class MockFlowExtractorFull : public core::IFlowExtractor {
public:
    MOCK_METHOD(void, setFlowCompletionCallback, (FlowCompletionCallback), (override));
    MOCK_METHOD(std::vector<std::vector<float>>, extractFeatures,
                (const std::string&), (override));
    MOCK_METHOD((const std::vector<core::FlowInfo>&), flowMetadata, (),
                (const, noexcept, override));
    MOCK_METHOD(void, processPacket,
                (const std::uint8_t*, std::size_t, std::int64_t), (override));
    MOCK_METHOD(void, finalizeAllFlows, (), (override));
    MOCK_METHOD(void, reset, (), (override));
    void setFlowTimeout(std::int64_t /*timeoutUs*/) override {}
    void setMaxFlowDuration(std::int64_t /*durationUs*/) override {}

    /// Set up ON_CALL to capture the FlowCompletionCallback for later use.
    void captureCallback() {
        ON_CALL(*this, setFlowCompletionCallback(::testing::_))
            .WillByDefault(::testing::Invoke(
                [this](FlowCompletionCallback cb) {
                    callback_ = std::move(cb);
                }));
    }

    /// Fire the captured FlowCompletionCallback with the given data.
    void fireFlowCompletion(std::vector<float>&& features, core::FlowInfo&& info) {
        if (callback_) {
            callback_(std::move(features), std::move(info));
        }
    }

private:
    FlowCompletionCallback callback_;
};

} // namespace nids::testing
