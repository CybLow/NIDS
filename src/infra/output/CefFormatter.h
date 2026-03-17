#pragma once

/// ArcSight Common Event Format (CEF) formatter.
///
/// Produces CEF:0 messages from DetectionResult + FlowInfo for forwarding
/// to SIEM platforms (ArcSight, QRadar, Splunk, Elastic).
///
/// Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <cstddef>
#include <string>

namespace nids::infra {

class CefFormatter {
public:
    /// Format a detection result as a CEF string.
    [[nodiscard]] std::string format(std::size_t flowIndex,
                                     const core::DetectionResult& result,
                                     const core::FlowInfo& flow) const;

private:
    /// Map combinedScore [0.0, 1.0] to CEF severity [0, 10].
    [[nodiscard]] static int cefSeverity(float combinedScore) noexcept;

    /// Escape pipe characters in CEF header fields.
    [[nodiscard]] static std::string escapeHeader(std::string_view value);

    /// Escape equals/backslash in CEF extension values.
    [[nodiscard]] static std::string escapeExtension(std::string_view value);
};

} // namespace nids::infra
