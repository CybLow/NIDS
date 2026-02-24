#pragma once

namespace nids::platform {

bool initializeNetworking();
void cleanupNetworking();

class NetworkInitGuard {
public:
    NetworkInitGuard();
    ~NetworkInitGuard();
    NetworkInitGuard(const NetworkInitGuard&) = delete;
    NetworkInitGuard& operator=(const NetworkInitGuard&) = delete;

    [[nodiscard]] bool isInitialized() const noexcept { return initialized_; }

private:
    bool initialized_;
};

} // namespace nids::platform
