#pragma once

namespace nids::platform {

/** Initialize platform networking (WSAStartup on Windows, no-op on POSIX). */
bool initializeNetworking();
/** Shut down platform networking (WSACleanup on Windows, no-op on POSIX). */
void cleanupNetworking();

/** RAII guard that initializes networking on construction and cleans up on destruction. */
class NetworkInitGuard {
public:
    /** Initialize networking. Check isInitialized() for success. */
    NetworkInitGuard();
    /** Clean up networking if it was successfully initialized. */
    ~NetworkInitGuard();
    NetworkInitGuard(const NetworkInitGuard&) = delete;
    NetworkInitGuard& operator=(const NetworkInitGuard&) = delete;

    /** Whether networking was successfully initialized. */
    [[nodiscard]] bool isInitialized() const noexcept { return initialized_; }

private:
    bool initialized_ = false;
};

} // namespace nids::platform
