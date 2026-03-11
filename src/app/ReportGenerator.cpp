#include "app/ReportGenerator.h"
#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"

#include <fstream>
#include <chrono>
#include <iomanip>

namespace nids::app {

namespace {

void writePacketHeader(std::ofstream& file, std::size_t index,
                       const nids::core::PacketInfo& pkt,
                       const nids::core::DetectionResult& detection) {
    file << "Packet #" << index << "\n";
    file << "  Protocol: " << pkt.protocol << "\n";
    file << "  Application: " << pkt.application << "\n";
    file << "  Source: " << pkt.ipSource << ":" << pkt.portSource << "\n";
    file << "  Destination: " << pkt.ipDestination << ":" << pkt.portDestination << "\n";
    file << "  Status: " << nids::core::attackTypeToString(detection.finalVerdict) << "\n";
}

void writeThreatIntelMatches(std::ofstream& file,
                              const std::vector<nids::core::ThreatIntelMatch>& matches) {
    file << "  Threat Intel Matches:\n";
    for (const auto& ti : matches) {
        file << "    - " << ti.ip << " [" << ti.feedName << "]"
             << (ti.isSource ? " (source)" : " (destination)") << "\n";
    }
}

void writeRuleMatches(std::ofstream& file,
                       const std::vector<nids::core::RuleMatch>& matches) {
    file << "  Heuristic Rules:\n";
    for (const auto& rule : matches) {
        file << "    - " << rule.ruleName << " (severity="
             << std::fixed << std::setprecision(2) << rule.severity
             << "): " << rule.description << "\n";
    }
}

void writeDetectionDetails(std::ofstream& file,
                            const nids::core::DetectionResult& detection) {
    file << "  Detection Source: "
         << nids::core::detectionSourceToString(detection.detectionSource) << "\n";
    file << "  Combined Score: " << std::fixed << std::setprecision(3)
         << detection.combinedScore << "\n";
    file << "  ML Confidence: " << std::fixed << std::setprecision(3)
         << detection.mlResult.confidence << "\n";

    if (!detection.threatIntelMatches.empty()) {
        writeThreatIntelMatches(file, detection.threatIntelMatches);
    }
    if (!detection.ruleMatches.empty()) {
        writeRuleMatches(file, detection.ruleMatches);
    }
}

} // anonymous namespace

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

        writePacketHeader(file, i, pkt, detection);

        if (detection.detectionSource != nids::core::DetectionSource::None) {
            writeDetectionDetails(file, detection);
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
