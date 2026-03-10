#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"

#include <optional>
#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

class CaptureSession {
public:
    void addPacket(const PacketInfo& packet);
    void setAnalysisResult(std::size_t index, AttackType type);

    /// Store a full hybrid detection result for a flow.
    /// Also updates the legacy AttackType vector with the final verdict.
    void setDetectionResult(std::size_t index, const DetectionResult& result);

    [[nodiscard]] const PacketInfo& getPacket(std::size_t index) const;
    [[nodiscard]] AttackType getAnalysisResult(std::size_t index) const;

    /// Retrieve the full detection result for a flow, if available.
    [[nodiscard]] std::optional<DetectionResult> getDetectionResult(std::size_t index) const;

    [[nodiscard]] std::size_t packetCount() const;
    [[nodiscard]] std::size_t analysisResultCount() const;

    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<PacketInfo> packets_;
    std::vector<AttackType> analysisResults_;
    std::vector<std::optional<DetectionResult>> detectionResults_;
};

} // namespace nids::core
