#pragma once

/// BypassManager — tracks clean flows for kernel-level bypass.
///
/// After a flow has been forwarded for a configurable number of packets
/// without triggering any detection, it can be bypassed (skip further
/// inspection) to reduce CPU overhead.

#include "core/model/FlowKey.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace nids::app {

/// Policy for deciding when to bypass a flow.
struct BypassPolicy {
    int cleanPacketThreshold = 100;   ///< Bypass after N clean packets
    int cleanFlowTimeSeconds = 30;    ///< Bypass after N seconds clean
    bool enabled = true;
};

class BypassManager {
public:
    explicit BypassManager(BypassPolicy policy = {});

    /// Track a forwarded (clean) packet for a flow.
    void trackForwarded(const core::FlowKey& key, int64_t nowUs);

    /// Check if a flow should be bypassed.
    [[nodiscard]] bool shouldBypass(const core::FlowKey& key) const;

    /// Mark a flow as bypassed (explicitly, e.g., after ML confirms benign).
    void markBypassed(const core::FlowKey& key);

    /// Revoke bypass for a flow (if a new alert triggers).
    void revokeBypass(const core::FlowKey& key);

    /// Clean up expired flow tracking.
    void sweep(int64_t nowUs, int64_t timeoutUs);

    /// Number of currently bypassed flows.
    [[nodiscard]] std::size_t bypassedFlowCount() const;

    /// Number of tracked flows.
    [[nodiscard]] std::size_t trackedFlowCount() const;

    /// Update bypass policy.
    void setPolicy(const BypassPolicy& policy);

private:
    struct FlowTracker {
        int cleanPackets = 0;
        int64_t firstSeenUs = 0;
        int64_t lastSeenUs = 0;
        bool bypassed = false;
    };

    BypassPolicy policy_;
    std::unordered_map<core::FlowKey, FlowTracker, core::FlowKeyHash> flows_;
    mutable std::mutex mutex_;
};

} // namespace nids::app
