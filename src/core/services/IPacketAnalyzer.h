#pragma once

#include "core/model/AttackType.h"

#include <vector>
#include <string>

namespace nids::core {

class IPacketAnalyzer {
public:
    virtual ~IPacketAnalyzer() = default;

    [[nodiscard]] virtual bool loadModel(const std::string& modelPath) = 0;
    [[nodiscard]] virtual AttackType predict(const std::vector<float>& features) = 0;
};

} // namespace nids::core
