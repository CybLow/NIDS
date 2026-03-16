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

class GrpcStreamSink : public nids::core::IOutputSink {
public:
    using EventQueue = nids::core::BoundedQueue<::nids::DetectionEvent>;

    explicit GrpcStreamSink(std::shared_ptr<EventQueue> queue,
                            ::nids::DetectionFilter filter);

    [[nodiscard]] std::string_view name() const noexcept override {
        return "GrpcStreamSink";
    }

    void onFlowResult(std::size_t flowIndex,
                      const nids::core::DetectionResult& result,
                      const nids::core::FlowInfo& flow) override;

private:
    std::shared_ptr<EventQueue> queue_;
    ::nids::DetectionFilter filter_;

    static void populateDetectionEvent(::nids::DetectionEvent& event,
                                       std::size_t flowIndex,
                                       const nids::core::DetectionResult& result,
                                       const nids::core::FlowInfo& flow);
};

} // namespace nids::server
