#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/AttackType.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

class CaptureSession {
public:
    void addPacket(const PacketInfo& packet);
    void setAnalysisResult(std::size_t index, AttackType type);

    [[nodiscard]] const PacketInfo& getPacket(std::size_t index) const;
    [[nodiscard]] AttackType getAnalysisResult(std::size_t index) const;
    [[nodiscard]] std::size_t packetCount() const;
    [[nodiscard]] std::size_t analysisResultCount() const;

    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<PacketInfo> packets_;
    std::vector<AttackType> analysisResults_;
};

} // namespace nids::core
