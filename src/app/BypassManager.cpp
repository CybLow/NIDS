#include "app/BypassManager.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <utility>

namespace nids::app {

BypassManager::BypassManager(BypassPolicy policy)
    : policy_(std::move(policy)) {}

void BypassManager::trackForwarded(const core::FlowKey& key,
                                    int64_t nowUs) {
    if (!policy_.enabled) return;

    std::scoped_lock lock{mutex_};
    auto& tracker = flows_[key];
    if (tracker.firstSeenUs == 0) {
        tracker.firstSeenUs = nowUs;
    }
    tracker.lastSeenUs = nowUs;
    ++tracker.cleanPackets;

    // Check if threshold reached.
    if (!tracker.bypassed &&
        tracker.cleanPackets >= policy_.cleanPacketThreshold) {
        tracker.bypassed = true;
        spdlog::debug("BypassManager: bypassing flow {}:{} -> {}:{} "
                      "after {} clean packets",
                      key.srcIp, key.srcPort, key.dstIp, key.dstPort,
                      tracker.cleanPackets);
    }
}

bool BypassManager::shouldBypass(const core::FlowKey& key) const {
    if (!policy_.enabled) return false;

    std::scoped_lock lock{mutex_};
    auto it = flows_.find(key);
    if (it == flows_.end()) return false;
    return it->second.bypassed;
}

void BypassManager::markBypassed(const core::FlowKey& key) {
    std::scoped_lock lock{mutex_};
    flows_[key].bypassed = true;
}

void BypassManager::revokeBypass(const core::FlowKey& key) {
    std::scoped_lock lock{mutex_};
    auto it = flows_.find(key);
    if (it != flows_.end()) {
        it->second.bypassed = false;
        it->second.cleanPackets = 0;
    }
}

void BypassManager::sweep(int64_t nowUs, int64_t timeoutUs) {
    std::scoped_lock lock{mutex_};
    std::erase_if(flows_, [nowUs, timeoutUs](const auto& pair) {
        return (nowUs - pair.second.lastSeenUs) > timeoutUs;
    });
}

std::size_t BypassManager::bypassedFlowCount() const {
    std::scoped_lock lock{mutex_};
    std::size_t count = 0;
    for (const auto& [key, tracker] : flows_) {
        if (tracker.bypassed) ++count;
    }
    return count;
}

std::size_t BypassManager::trackedFlowCount() const {
    std::scoped_lock lock{mutex_};
    return flows_.size();
}

void BypassManager::setPolicy(const BypassPolicy& policy) {
    policy_ = policy;
}

} // namespace nids::app
