#include "infra/platform/NetfilterBlocker.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <ranges>

namespace nids::infra {

NetfilterBlocker::NetfilterBlocker(bool dryRun) : dryRun_(dryRun) {}

NetfilterBlocker::~NetfilterBlocker() {
    try {
        clearAll();
    } catch (...) {
        // Destructors must not throw.
    }
}

bool NetfilterBlocker::block(const FlowKey& key,
                              std::string reason,
                              std::chrono::seconds duration) {
    std::scoped_lock lock{mutex_};

    // Check for duplicate.
    auto existing = std::ranges::find_if(activeBlocks_,
        [&key](const auto& entry) { return entry.key == key; });
    if (existing != activeBlocks_.end()) {
        // Refresh expiry.
        existing->expiresAt = std::chrono::steady_clock::now() + duration;
        return true;
    }

    BlockEntry entry;
    entry.key = key;
    entry.reason = std::move(reason);
    entry.expiresAt = std::chrono::steady_clock::now() + duration;

    activeBlocks_.push_back(std::move(entry));

    if (!dryRun_) {
        spdlog::info("NetfilterBlocker: blocked {}:{} -> {}:{} proto={} "
                     "for {}s",
                     key.srcIp, key.srcPort, key.dstIp, key.dstPort,
                     key.protocol, duration.count());
    }

    return true;
}

bool NetfilterBlocker::unblock(const FlowKey& key) {
    std::scoped_lock lock{mutex_};

    auto it = std::ranges::find_if(activeBlocks_,
        [&key](const auto& entry) { return entry.key == key; });

    if (it == activeBlocks_.end()) return false;

    if (!dryRun_) {
        spdlog::info("NetfilterBlocker: unblocked {}:{} -> {}:{}",
                     key.srcIp, key.srcPort, key.dstIp, key.dstPort);
    }

    activeBlocks_.erase(it);
    return true;
}

void NetfilterBlocker::clearAll() {
    std::scoped_lock lock{mutex_};
    if (!dryRun_ && !activeBlocks_.empty()) {
        spdlog::info("NetfilterBlocker: clearing {} block rules",
                     activeBlocks_.size());
    }
    activeBlocks_.clear();
}

void NetfilterBlocker::sweepExpired() {
    std::scoped_lock lock{mutex_};
    const auto now = std::chrono::steady_clock::now();

    std::erase_if(activeBlocks_, [&now, this](const auto& entry) {
        if (entry.expiresAt <= now) {
            if (!dryRun_) {
                spdlog::debug("NetfilterBlocker: expired block for "
                              "{}:{} -> {}:{}",
                              entry.key.srcIp, entry.key.srcPort,
                              entry.key.dstIp, entry.key.dstPort);
            }
            return true;
        }
        return false;
    });
}

std::size_t NetfilterBlocker::activeRuleCount() const {
    std::scoped_lock lock{mutex_};
    return activeBlocks_.size();
}

bool NetfilterBlocker::isBlocked(const FlowKey& key) const {
    std::scoped_lock lock{mutex_};
    return std::ranges::any_of(activeBlocks_,
        [&key](const auto& entry) { return entry.key == key; });
}

} // namespace nids::infra
