#include "infra/platform/SocketInit.h"

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
#endif

namespace nids::platform {

bool initializeNetworking() {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

void cleanupNetworking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

NetworkInitGuard::NetworkInitGuard()
    : initialized_(initializeNetworking()) {}

NetworkInitGuard::~NetworkInitGuard() {
    if (initialized_) {
        cleanupNetworking();
    }
}

} // namespace nids::platform
