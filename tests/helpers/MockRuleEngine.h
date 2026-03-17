#pragma once

/// Shared mock for IRuleEngine.

#include <gmock/gmock.h>

#include "core/services/IRuleEngine.h"

#include <cstdint>
#include <string_view>
#include <vector>

namespace nids::testing {

class MockRuleEngine : public core::IRuleEngine {
public:
    MOCK_METHOD(std::vector<core::RuleMatch>, evaluate,
                (const core::FlowInfo&), (const, override));
    MOCK_METHOD(std::vector<core::RuleMatch>, evaluatePortScan,
                (std::string_view, const std::vector<std::uint16_t>&),
                (const, override));
    MOCK_METHOD(std::size_t, ruleCount, (), (const, noexcept, override));
};

} // namespace nids::testing
