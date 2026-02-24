#include "infra/platform/SocketInit.h"
#include "infra/capture/PcapCapture.h"
#include "infra/analysis/FdeepAnalyzer.h"
#include "infra/flow/CsvFlowProcessor.h"
#include "app/CaptureController.h"
#include "app/AnalysisService.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <memory>
#include <iostream>

int main(int argc, char* argv[]) {
    nids::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        std::cerr << "Failed to initialize networking" << std::endl;
        return 1;
    }

    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication app(argc, argv);

    qRegisterMetaType<nids::core::PacketInfo>("nids::core::PacketInfo");

    auto capture = std::make_unique<nids::infra::PcapCapture>();
    auto controller = std::make_unique<nids::app::CaptureController>(std::move(capture));

    auto analyzer = std::make_unique<nids::infra::FdeepAnalyzer>();
    auto flowExtractor = std::make_unique<nids::infra::CsvFlowProcessor>();
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(analyzer), std::move(flowExtractor));

    nids::ui::MainWindow window(std::move(controller), std::move(analysisService));
    window.show();

    return app.exec();
}
