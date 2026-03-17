#pragma once

/// gRPC output sink that queues detection events for streaming to clients.
///
/// Each connected StreamDetections client gets its own GrpcStreamSink
/// backed by a per-client BoundedQueue.  The pipeline pushes events into
/// the queue, and the gRPC streaming handler reads from it.

#include "core/concurrent/BoundedQueue.h"
#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"
#include "core/services/IOutputSink.h"

#include <nids.pb.h>

#include <cstddef>
#include <memory>
#include <string_view>

namespace nids::server {

class GrpcStreamSink : public core::IOutputSink {
public:
    using EventQueue = core::BoundedQueue<DetectionEvent>;

    explicit GrpcStreamSink(std::shared_ptr<EventQueue> queue,
                            DetectionFilter filter);

    [[nodiscard]] std::string_view name() const noexcept override {
        return "GrpcStreamSink";
    }

    void onFlowResult(std::size_t flowIndex,
                      const core::DetectionResult& result,
                      const core::FlowInfo& flow) override;

private:
    std::shared_ptr<EventQueue> queue_;
    DetectionFilter filter_;

    static void populateDetectionEvent(DetectionEvent& event,
                                       std::size_t flowIndex,
                                       const core::DetectionResult& result,
                                       const core::FlowInfo& flow);

    /// Populate the flow metadata section of a DetectionEvent.
    static void populateFlowMetadata(DetectionEvent& event,
                                     const core::FlowInfo& flow);

    /// Populate the ML classification + probabilities section.
    static void populateMlClassification(DetectionEvent& event,
                                         const core::DetectionResult& result);

    /// Populate TI/rule matches and the combined verdict.
    static void populateMatchesAndVerdict(DetectionEvent& event,
                                          const core::DetectionResult& result);
};

} // namespace nids::server
