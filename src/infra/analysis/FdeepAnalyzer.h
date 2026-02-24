#pragma once

#include "core/services/IPacketAnalyzer.h"

#include <memory>
#include <string>

namespace fdeep { class model; }

namespace nids::infra {

class FdeepAnalyzer : public nids::core::IPacketAnalyzer {
public:
    FdeepAnalyzer();
    ~FdeepAnalyzer() override;

    [[nodiscard]] bool loadModel(const std::string& modelPath) override;
    [[nodiscard]] nids::core::AttackType predict(const std::vector<float>& features) override;

private:
    std::unique_ptr<fdeep::model> model_;
    bool loaded_ = false;
};

} // namespace nids::infra
