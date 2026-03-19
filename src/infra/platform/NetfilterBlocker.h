#pragma once

/// NetfilterBlocker — inserts dynamic block rules via nftables/iptables.
///
/// Used by VerdictEngine to block flows at the kernel level after
/// ML detection. Tracks active block rules and sweeps expired ones.

#include "infra/flow/FlowKey.h"

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

namespace nids::infra {

class NetfilterBlocker {
public:
    explicit NetfilterBlocker(bool dryRun = false);
    ~NetfilterBlocker();

    NetfilterBlocker(const NetfilterBlocker&) = delete;
    NetfilterBlocker& operator=(const NetfilterBlocker&) = delete;

    /// Block a specific 5-tuple for a duration.
    [[nodiscard]] bool block(const FlowKey& key,
                              std::string reason,
                              std::chrono::seconds duration =
                                  std::chrono::seconds{300});

    /// Unblock a specific 5-tuple.
    [[nodiscard]] bool unblock(const FlowKey& key);

    /// Remove all NIDS-managed block rules.
    void clearAll();

    /// Remove expired block rules.
    void sweepExpired();

    /// Number of active block rules.
    [[nodiscard]] std::size_t activeRuleCount() const;

    /// Check if a flow is blocked.
    [[nodiscard]] bool isBlocked(const FlowKey& key) const;

private:
    struct BlockEntry {
        FlowKey key;
        std::string reason;
        std::chrono::steady_clock::time_point expiresAt;
    };

    bool dryRun_;  ///< If true, don't execute system commands.
    std::vector<BlockEntry> activeBlocks_;
    mutable std::mutex mutex_;
};

} // namespace nids::infra
