#include "app/ReportGenerator.h"
#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"

#include <fstream>
#include <chrono>
#include <iomanip>

namespace nids::app {

ReportGenerator::ReportResult ReportGenerator::generate(
    const nids::core::CaptureSession& session,
    const std::string& filePath,
    const std::string& networkCard) {

    ReportResult result;
    result.filePath = filePath;

    auto start = std::chrono::steady_clock::now();

    std::ofstream file(filePath);
    if (!file.is_open()) {
        result.success = false;
        return result;
    }

    file << "NIDS Capture Report\n";
    file << "===================\n\n";

    if (!networkCard.empty()) {
        file << "Interface: " << networkCard << "\n";
    }
    file << "Total packets: " << session.packetCount() << "\n\n";

    std::size_t count = session.packetCount();
    for (std::size_t i = 0; i < count; ++i) {
        const auto& pkt = session.getPacket(i);
        auto detection = session.getDetectionResult(i);

        file << "Packet #" << i << "\n";
        file << "  Protocol: " << pkt.protocol << "\n";
        file << "  Application: " << pkt.application << "\n";
        file << "  Source: " << pkt.ipSource << ":" << pkt.portSource << "\n";
        file << "  Destination: " << pkt.ipDestination << ":" << pkt.portDestination << "\n";
        file << "  Status: " << nids::core::attackTypeToString(detection.finalVerdict) << "\n";

        // Append hybrid detection details when available
        if (detection.detectionSource != nids::core::DetectionSource::None) {
            file << "  Detection Source: " << nids::core::detectionSourceToString(detection.detectionSource) << "\n";
            file << "  Combined Score: " << std::fixed << std::setprecision(3) << detection.combinedScore << "\n";
            file << "  ML Confidence: " << std::fixed << std::setprecision(3) << detection.mlResult.confidence << "\n";

            if (!detection.threatIntelMatches.empty()) {
                file << "  Threat Intel Matches:\n";
                for (const auto& ti : detection.threatIntelMatches) {
                    file << "    - " << ti.ip << " [" << ti.feedName << "]"
                         << (ti.isSource ? " (source)" : " (destination)") << "\n";
                }
            }

            if (!detection.ruleMatches.empty()) {
                file << "  Heuristic Rules:\n";
                for (const auto& rule : detection.ruleMatches) {
                    file << "    - " << rule.ruleName << " (severity="
                         << std::fixed << std::setprecision(2) << rule.severity
                         << "): " << rule.description << "\n";
                }
            }
        }

        file << "\n";
    }

    file.close();

    auto end = std::chrono::steady_clock::now();
    result.generationTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    result.success = true;

    return result;
}

} // namespace nids::app
