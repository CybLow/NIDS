#pragma once

/// Shared mock for IOutputSink.

#include <gmock/gmock.h>

#include "core/services/IOutputSink.h"

#include <cstddef>
#include <string_view>

namespace nids::testing {

class MockOutputSink : public core::IOutputSink {
public:
    MOCK_METHOD(std::string_view, name, (), (const, noexcept, override));
    MOCK_METHOD(bool, start, (), (override));
    MOCK_METHOD(void, onFlowResult,
                (std::size_t, const core::DetectionResult&, const core::FlowInfo&),
                (override));
    MOCK_METHOD(void, stop, (), (override));
};

} // namespace nids::testing
