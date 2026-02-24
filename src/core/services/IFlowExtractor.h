#pragma once

#include <string>
#include <vector>

namespace nids::core {

class IFlowExtractor {
public:
    virtual ~IFlowExtractor() = default;

    [[nodiscard]] virtual bool extractFlows(const std::string& pcapPath,
                                            const std::string& outputCsvPath) = 0;

    [[nodiscard]] virtual std::vector<std::vector<float>> loadFeatures(
        const std::string& csvPath) = 0;
};

} // namespace nids::core
