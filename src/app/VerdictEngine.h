#pragma once

/// VerdictEngine — combines all detection signals into per-packet verdicts.
///
/// Runs on the hot path (<1ms per packet). Checks TI, signatures, YARA,
/// and dynamic block list to produce a Forward/Drop/Reject/Alert decision.

#include "core/model/FlowInfo.h"
#include "core/model/PacketVerdict.h"
#include "core/model/FlowKey.h"

#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <unordered_set>

namespace nids::core {
class IThreatIntelligence;
class ISignatureEngine;
class IContentScanner;
} // namespace nids::core

namespace nids::app {

/// Policy controlling which detection signals cause packet drops.
struct VerdictPolicy {
    bool blockOnTiMatch = true;
    bool blockOnSignature = true;
    bool blockOnYara = false;       ///< Alert only for YARA by default
    bool blockOnMlVerdict = true;
    float mlBlockThreshold = 0.85f;
};

class VerdictEngine {
public:
    VerdictEngine(core::IThreatIntelligence* threatIntel,
                  core::ISignatureEngine* signatures,
                  core::IContentScanner* yaraScanner,
                  VerdictPolicy policy = {});

    /// Determine verdict for a single packet.
    [[nodiscard]] core::VerdictResult evaluate(
        std::span<const std::uint8_t> payload,
        const core::FlowInfo& flow) const;

    /// Check if a flow is dynamically blocked.
    [[nodiscard]] bool isBlocked(const core::FlowKey& key) const;

    /// Add a dynamic block for a flow (from ML verdict).
    void blockFlow(const core::FlowKey& key, std::string reason);

    /// Remove a dynamic block.
    void unblockFlow(const core::FlowKey& key);

    /// Clear all dynamic blocks.
    void clearBlocks();

    /// Number of active dynamic blocks.
    [[nodiscard]] std::size_t blockCount() const;

    /// Update the verdict policy.
    void setPolicy(const VerdictPolicy& policy);

private:
    core::IThreatIntelligence* threatIntel_;
    core::ISignatureEngine* signatures_;
    core::IContentScanner* yaraScanner_;
    VerdictPolicy policy_;

    mutable std::mutex blockMutex_;
    std::unordered_set<core::FlowKey, core::FlowKeyHash> blockedFlows_;
};

} // namespace nids::app
