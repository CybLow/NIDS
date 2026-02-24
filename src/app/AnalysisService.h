#pragma once

#include "core/model/CaptureSession.h"
#include "core/model/AttackType.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

class AnalysisService : public QObject {
    Q_OBJECT

public:
    explicit AnalysisService(std::unique_ptr<nids::core::IPacketAnalyzer> analyzer,
                             std::unique_ptr<nids::core::IFlowExtractor> extractor,
                             QObject* parent = nullptr);

    [[nodiscard]] bool loadModel(const std::string& modelPath);

    void analyzeCapture(const std::string& pcapPath,
                        nids::core::CaptureSession& session);

signals:
    void analysisStarted();
    void analysisProgress(int current, int total);
    void analysisFinished();
    void analysisError(const QString& message);

private:
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer_;
    std::unique_ptr<nids::core::IFlowExtractor> extractor_;
};

} // namespace nids::app
