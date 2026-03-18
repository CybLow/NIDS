#pragma once

/// TimelineEvent — a single event in an incident timeline.
///
/// Used by TimelineBuilder to construct a chronological narrative of
/// an attack or suspicious activity for incident-response reports.

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace nids::core {

/// Classification of an event within an attack timeline.
enum class EventType : std::uint8_t {
    FirstContact,    ///< First flow from attacker IP
    Reconnaissance,  ///< Port scan or network sweep
    Exploitation,    ///< Attack flow detected by ML/rules
    LateralMovement, ///< Internal-to-internal after external attack
    Exfiltration,    ///< Large outbound data transfer
    Persistence,     ///< Repeated connections over time
};

struct TimelineEvent {
    int64_t timestampUs = 0;
    std::string description;
    FlowInfo flow;
    DetectionResult detection;
    EventType type = EventType::FirstContact;
};

/// A complete incident timeline.
struct Timeline {
    std::string incidentId;
    std::string summary;
    std::vector<TimelineEvent> events;
    int64_t startTimeUs = 0;
    int64_t endTimeUs = 0;
    std::vector<std::string> involvedIps;
    std::vector<AttackType> attackTypes;
};

} // namespace nids::core
