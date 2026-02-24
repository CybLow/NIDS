#pragma once

#include "core/model/CaptureSession.h"

#include <string>

namespace nids::app {

class ReportGenerator {
public:
    struct ReportResult {
        bool success = false;
        std::string filePath;
        int64_t generationTimeMs = 0;
    };

    [[nodiscard]] static ReportResult generate(
        const nids::core::CaptureSession& session,
        const std::string& filePath,
        const std::string& networkCard = "");
};

} // namespace nids::app
