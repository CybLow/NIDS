#pragma once

#include "core/model/CaptureSession.h"

#include <string>

namespace nids::app {

/** Generates HTML analysis reports from a capture session. */
class ReportGenerator {
public:
    /** Result of a report generation attempt. */
    struct ReportResult {
        /** Whether the report was generated successfully. */
        bool success = false;
        /** Absolute path to the generated report file. */
        std::string filePath;
        /** Time taken to generate the report, in milliseconds. */
        int64_t generationTimeMs = 0;
    };

    /**
     * Generate an HTML report for the given capture session.
     * @param session      The capture session containing packets and analysis results.
     * @param filePath     Output file path for the report.
     * @param networkCard  Optional network interface name to include in the report.
     * @return Result indicating success/failure and generation time.
     */
    [[nodiscard]] static ReportResult generate(
        const nids::core::CaptureSession& session,
        const std::string& filePath,
        const std::string& networkCard = "");
};

} // namespace nids::app
