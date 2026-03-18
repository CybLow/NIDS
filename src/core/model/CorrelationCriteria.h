#pragma once

/// CorrelationCriteria — parameters for correlating related network flows.
///
/// Used by FlowCorrelator to group flows that suggest coordinated attacks,
/// lateral movement, or scanning activity.

#include <cstddef>
#include <cstdint>

namespace nids::core {

/// Strategy for correlating flows.
enum class CorrelationStrategy : std::uint8_t {
    SameSourceIp,     ///< All flows from the same attacker
    SameDestIp,       ///< All flows to the same target
    PortSweep,        ///< Same src, many dst ports
    NetworkSweep,     ///< Same src, many dst IPs
    LateralMovement,  ///< Internal-to-internal after external attack
    TemporalProximity ///< Flows within N seconds of each other
};

struct CorrelationCriteria {
    CorrelationStrategy strategy = CorrelationStrategy::SameSourceIp;
    int64_t windowUs = 300'000'000;  ///< 5-minute correlation window
    std::size_t minFlows = 3;        ///< Minimum flows to form a group
};

} // namespace nids::core
