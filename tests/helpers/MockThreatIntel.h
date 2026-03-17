#pragma once

/// Shared mock for IThreatIntelligence.

#include <gmock/gmock.h>

#include "core/services/IThreatIntelligence.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nids::testing {

class MockThreatIntel : public core::IThreatIntelligence {
public:
    MOCK_METHOD(std::size_t, loadFeeds, (const std::string&), (override));
    MOCK_METHOD(core::ThreatIntelLookup, lookup, (std::string_view),
                (const, override));
    MOCK_METHOD(core::ThreatIntelLookup, lookup, (std::uint32_t),
                (const, override));
    MOCK_METHOD(std::size_t, entryCount, (), (const, noexcept, override));
    MOCK_METHOD(std::size_t, feedCount, (), (const, noexcept, override));
    MOCK_METHOD(std::vector<std::string>, feedNames, (), (const, override));
};

} // namespace nids::testing
