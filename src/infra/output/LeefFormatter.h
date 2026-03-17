#pragma once

/// IBM QRadar Log Event Extended Format (LEEF) formatter.
///
/// Produces LEEF:2.0 messages from DetectionResult + FlowInfo for forwarding
/// to QRadar and SIEM platforms that consume LEEF.
///
/// Format: LEEF:2.0|Vendor|Product|Version|EventID|\t-separated key=value

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <cstddef>
#include <string>

namespace nids::infra {

class LeefFormatter {
public:
    /// Format a detection result as a LEEF 2.0 string.
    [[nodiscard]] std::string format(std::size_t flowIndex,
                                     const core::DetectionResult& result,
                                     const core::FlowInfo& flow) const;

private:
    /// Map combinedScore [0.0, 1.0] to LEEF severity [1, 10].
    [[nodiscard]] static int leefSeverity(float combinedScore) noexcept;
};

} // namespace nids::infra
