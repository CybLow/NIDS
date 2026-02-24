#pragma once

#include "core/model/PacketInfo.h"

#include <functional>
#include <string>
#include <vector>

namespace nids::core {

class IPacketCapture {
public:
    virtual ~IPacketCapture() = default;

    using PacketCallback = std::function<void(const PacketInfo&)>;

    [[nodiscard]] virtual bool initialize(const std::string& interface,
                                          const std::string& bpfFilter) = 0;
    virtual void startCapture(const std::string& dumpFile) = 0;
    virtual void stopCapture() = 0;
    [[nodiscard]] virtual bool isCapturing() const = 0;

    virtual void setPacketCallback(PacketCallback callback) = 0;

    [[nodiscard]] virtual std::vector<std::string> listInterfaces() = 0;
};

} // namespace nids::core
