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
        auto attackType = session.getAnalysisResult(i);
        auto detection = session.getDetectionResult(i);

        file << "Packet #" << i << "\n";
        file << "  Protocol: " << pkt.protocol << "\n";
        file << "  Application: " << pkt.application << "\n";
        file << "  Source: " << pkt.ipSource << ":" << pkt.portSource << "\n";
        file << "  Destination: " << pkt.ipDestination << ":" << pkt.portDestination << "\n";
        file << "  Status: " << nids::core::attackTypeToString(attackType) << "\n";

        // Append hybrid detection details if available
        if (detection.has_value()) {
            const auto& det = detection.value();
            file << "  Detection Source: " << nids::core::detectionSourceToString(det.detectionSource) << "\n";
            file << "  Combined Score: " << std::fixed << std::setprecision(3) << det.combinedScore << "\n";
            file << "  ML Confidence: " << std::fixed << std::setprecision(3) << det.mlResult.confidence << "\n";

            if (!det.threatIntelMatches.empty()) {
                file << "  Threat Intel Matches:\n";
                for (const auto& ti : det.threatIntelMatches) {
                    file << "    - " << ti.ip << " [" << ti.feedName << "]"
                         << (ti.isSource ? " (source)" : " (destination)") << "\n";
                }
            }

            if (!det.ruleMatches.empty()) {
                file << "  Heuristic Rules:\n";
                for (const auto& rule : det.ruleMatches) {
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
