#pragma once

#include "core/services/IFlowExtractor.h"

#include <string>
#include <vector>

namespace nids::infra {

class CsvFlowProcessor : public nids::core::IFlowExtractor {
public:
    [[nodiscard]] bool extractFlows(const std::string& pcapPath,
                                    const std::string& outputCsvPath) override;

    [[nodiscard]] std::vector<std::vector<float>> loadFeatures(
        const std::string& csvPath) override;

private:
    [[nodiscard]] bool runCicFlowMeter(const std::string& pcapPath,
                                       const std::string& rawCsvPath) const;
    [[nodiscard]] bool cleanCsv(const std::string& inputPath,
                                const std::string& outputPath) const;
    [[nodiscard]] bool normalizeScientificNotation(const std::string& inputPath,
                                                    const std::string& outputPath) const;

    [[nodiscard]] std::vector<float> parseLine(const std::string& line) const;
    [[nodiscard]] static bool containsExponent(const std::string& s);
    [[nodiscard]] static std::string processScientificNotation(const std::string& s);
};

} // namespace nids::infra
