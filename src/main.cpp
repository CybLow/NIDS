#include "core/services/Configuration.h"
#include "infra/platform/SocketInit.h"
#include "infra/capture/PcapCapture.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "app/CaptureController.h"
#include "app/AnalysisService.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <spdlog/spdlog.h>

#include <memory>

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    nids::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        spdlog::critical("Failed to initialize networking");
        return 1;
    }

    auto& config = nids::core::Configuration::instance();

    QApplication app(argc, argv);

    qRegisterMetaType<nids::core::PacketInfo>("nids::core::PacketInfo");

    auto capture = std::make_unique<nids::infra::PcapCapture>();
    auto controller = std::make_unique<nids::app::CaptureController>(std::move(capture));

    auto analyzer = nids::infra::createAnalyzer();
    if (!analyzer->loadModel(config.modelPath().string())) {
        spdlog::warn("ML model not loaded from '{}' -- analysis will be unavailable",
                     config.modelPath().string());
    }

    auto flowExtractor = std::make_unique<nids::infra::NativeFlowExtractor>();
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(analyzer), std::move(flowExtractor));

    nids::ui::MainWindow window(std::move(controller), std::move(analysisService));
    window.show();

    return app.exec();
}
