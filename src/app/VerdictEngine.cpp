#include "app/VerdictEngine.h"

#include "core/services/IContentScanner.h"
#include "core/services/ISignatureEngine.h"
#include "core/services/IThreatIntelligence.h"

#include <spdlog/spdlog.h>

#include <utility>

namespace nids::app {

VerdictEngine::VerdictEngine(core::IThreatIntelligence* threatIntel,
                             core::ISignatureEngine* signatures,
                             core::IContentScanner* yaraScanner,
                             VerdictPolicy policy)
    : threatIntel_(threatIntel),
      signatures_(signatures),
      yaraScanner_(yaraScanner),
      policy_(std::move(policy)) {}

// ── evaluate() — hot path ───────────────────────────────────────────

core::VerdictResult VerdictEngine::evaluate(
    std::span<const std::uint8_t> payload,
    const core::FlowInfo& flow) const {

    // 1. Check dynamic block list (O(1) hash lookup).
    {
        core::FlowKey key{flow.srcIp, flow.dstIp,
                           flow.srcPort, flow.dstPort, flow.protocol};
        if (isBlocked(key)) {
            return {core::PacketVerdict::Drop,
                    core::VerdictSource::DynamicBlock,
                    "Flow dynamically blocked by ML verdict"};
        }
    }

    // 2. Threat intelligence IP lookup (O(1)).
    if (threatIntel_ && policy_.blockOnTiMatch) {
        auto srcLookup = threatIntel_->lookup(flow.srcIp);
        if (srcLookup.matched) {
            return {core::PacketVerdict::Drop,
                    core::VerdictSource::ThreatIntel,
                    "Source IP matched TI feed: " + srcLookup.feedName};
        }
        auto dstLookup = threatIntel_->lookup(flow.dstIp);
        if (dstLookup.matched) {
            return {core::PacketVerdict::Drop,
                    core::VerdictSource::ThreatIntel,
                    "Dest IP matched TI feed: " + dstLookup.feedName};
        }
    }

    // 3. Signature matching (Aho-Corasick).
    if (signatures_ && !payload.empty()) {
        auto sigMatches = signatures_->inspect(payload, flow);
        if (!sigMatches.empty()) {
            if (policy_.blockOnSignature) {
                return {core::PacketVerdict::Drop,
                        core::VerdictSource::Signature,
                        "Signature match: SID " +
                            std::to_string(sigMatches[0].sid) +
                            " - " + sigMatches[0].msg};
            }
            return {core::PacketVerdict::Alert,
                    core::VerdictSource::Signature,
                    "Signature alert: " + sigMatches[0].msg};
        }
    }

    // 4. YARA content scan (optional, per-packet shallow scan).
    if (yaraScanner_ && !payload.empty()) {
        auto yaraMatches = yaraScanner_->scan(payload);
        if (!yaraMatches.empty()) {
            if (policy_.blockOnYara) {
                return {core::PacketVerdict::Drop,
                        core::VerdictSource::YaraMatch,
                        "YARA match: " + yaraMatches[0].ruleName};
            }
            return {core::PacketVerdict::Alert,
                    core::VerdictSource::YaraMatch,
                    "YARA alert: " + yaraMatches[0].ruleName};
        }
    }

    // 5. Default: forward.
    return {core::PacketVerdict::Forward,
            core::VerdictSource::Default, {}};
}

// ── Dynamic block management ────────────────────────────────────────

bool VerdictEngine::isBlocked(const core::FlowKey& key) const {
    std::scoped_lock lock{blockMutex_};
    return blockedFlows_.contains(key);
}

void VerdictEngine::blockFlow(const core::FlowKey& key,
                               std::string reason) {
    std::scoped_lock lock{blockMutex_};
    if (blockedFlows_.insert(key).second) {
        spdlog::info("VerdictEngine: blocked flow {}:{} -> {}:{} ({})",
                     key.srcIp, key.srcPort, key.dstIp, key.dstPort,
                     reason);
    }
}

void VerdictEngine::unblockFlow(const core::FlowKey& key) {
    std::scoped_lock lock{blockMutex_};
    blockedFlows_.erase(key);
}

void VerdictEngine::clearBlocks() {
    std::scoped_lock lock{blockMutex_};
    blockedFlows_.clear();
}

std::size_t VerdictEngine::blockCount() const {
    std::scoped_lock lock{blockMutex_};
    return blockedFlows_.size();
}

void VerdictEngine::setPolicy(const VerdictPolicy& policy) {
    policy_ = policy;
}

} // namespace nids::app
