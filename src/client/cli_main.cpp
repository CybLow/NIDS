/// NIDS CLI client entry point.
///
/// Connects to a running nids-server via gRPC and provides command-line
/// control over capture sessions and detection streaming.
///
/// Usage:
///   nids-cli [--server addr:port] <command> [args...]
///
/// Commands:
///   status                          Show server status
///   interfaces                      List available network interfaces
///   capture start <iface> [--bpf]   Start a capture session
///   capture stop [session-id]       Stop the current capture
///   stream [--filter flagged|clean|all]   Stream detection events
///   help                            Show this help message

#include "client/NidsClient.h"

#include <nids.pb.h>

#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

// gRPC 1.72.0 has use-after-poison false positives in its epoll/thread-pool
// internals (abseil StatusRep::SetPayload) when compiled with GCC 15 + ASan.
// Disable user-poisoning detection to avoid false aborts from gRPC's arena.
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
extern "C" const char* __asan_default_options() {  // NOLINT
    return "allow_user_poisoning=0";
}
#endif

namespace {

std::atomic<bool> gStopStreaming{false};

void signalHandler(int /*signum*/) {
    gStopStreaming.store(true);
}

void printUsage(std::string_view progName) {
    std::cerr
        << "Usage: " << progName << " [--server addr:port] <command> [args...]\n"
        << "\n"
        << "Commands:\n"
        << "  status                              Show server status\n"
        << "  interfaces                          List network interfaces\n"
        << "  capture start <iface> [--bpf <f>]   Start capture\n"
        << "  capture stop [session-id]            Stop capture\n"
        << "  stream [--filter flagged|clean|all]  Stream detections\n"
        << "  help                                 Show this help\n"
        << "\n"
        << "Options:\n"
        << "  --server <addr:port>   Server address (default: localhost:50051)\n";
}

void cmdStatus(nids::client::NidsClient& client) {
    auto info = client.getStatus();
    std::cout << "Server Status:\n"
              << "  Capturing:   " << (info.capturing ? "yes" : "no") << "\n"
              << "  Interface:   " << (info.currentInterface.empty()
                                           ? "(none)" : info.currentInterface) << "\n"
              << "  Session ID:  " << (info.sessionId.empty()
                                           ? "(none)" : info.sessionId) << "\n"
              << "  Packets:     " << info.packetsCaptured << "\n"
              << "  Flows:       " << info.flowsDetected << "\n"
              << "  Flagged:     " << info.flowsFlagged << "\n"
              << "  Dropped:     " << info.flowsDropped << "\n";
}

void cmdListInterfaces(nids::client::NidsClient& client) {
    auto interfaces = client.listInterfaces();
    if (interfaces.empty()) {
        std::cout << "No interfaces available (check permissions).\n";
        return;
    }
    std::cout << "Available interfaces:\n";
    for (const auto& iface : interfaces) {
        std::cout << "  " << iface << "\n";
    }
}

void cmdCaptureStart(nids::client::NidsClient& client,
                     const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: interface name required\n";
        return;
    }

    const auto& iface = args[0];
    std::string bpf;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--bpf" && i + 1 < args.size()) {
            bpf = args[++i];
        }
    }

    auto sessionId = client.startCapture(iface, bpf);
    if (sessionId.empty()) {
        std::cerr << "Failed to start capture.\n";
        return;
    }
    std::cout << "Capture started. Session: " << sessionId << "\n";
}

void cmdCaptureStop(nids::client::NidsClient& client,
                    const std::vector<std::string>& args) {
    std::string sessionId;
    if (!args.empty()) {
        sessionId = args[0];
    }

    auto summary = client.stopCapture(sessionId);
    std::cout << summary << "\n";
}

void cmdStream(nids::client::NidsClient& client,
               const std::vector<std::string>& args) {
    ::nids::DetectionFilter filter = ::nids::FILTER_ALL;

    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--filter" && i + 1 < args.size()) {
            const auto& val = args[++i];
            if (val == "flagged") {
                filter = ::nids::FILTER_FLAGGED;
            } else if (val == "clean") {
                filter = ::nids::FILTER_CLEAN;
            } else if (val == "all") {
                filter = ::nids::FILTER_ALL;
            } else {
                std::cerr << "Unknown filter: " << val << "\n";
                return;
            }
        }
    }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::cout << "Streaming detections (Ctrl+C to stop)...\n\n";

    client.streamDetections("", filter,
        [](const ::nids::DetectionEvent& event) {
            const char* verdict =
                event.verdict() == ::nids::VERDICT_ATTACK ? "ATTACK" :
                event.verdict() == ::nids::VERDICT_BENIGN ? "BENIGN" :
                "UNKNOWN";

            std::cout << std::setw(6) << event.flow_index() << " | "
                      << std::left << std::setw(8) << verdict << " | "
                      << std::setw(15) << event.flow().src_ip() << ":"
                      << std::setw(5) << event.flow().src_port() << " -> "
                      << std::setw(15) << event.flow().dst_ip() << ":"
                      << std::setw(5) << event.flow().dst_port() << " | "
                      << std::setw(5) << event.flow().protocol() << " | "
                      << std::setw(20) << event.ml_classification() << " | "
                      << std::fixed << std::setprecision(3)
                      << event.ml_confidence() << " | "
                      << event.combined_score() << "\n";
        },
        gStopStreaming);

    std::cout << "\nStreaming stopped.\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::warn);

    nids::client::ClientConfig config;
    std::vector<std::string> positionalArgs;

    // Parse global options
    for (int i = 1; i < argc; ++i) {
        auto arg = std::string_view{argv[i]};
        if (arg == "--server" && i + 1 < argc) {
            config.serverAddress = argv[++i];
        } else {
            positionalArgs.emplace_back(argv[i]);
        }
    }

    if (positionalArgs.empty() || positionalArgs[0] == "help"
        || positionalArgs[0] == "--help" || positionalArgs[0] == "-h") {
        printUsage(argv[0]);
        return positionalArgs.empty() ? 1 : 0;
    }

    const auto& command = positionalArgs[0];

    // Connect to server
    nids::client::NidsClient client(config);
    if (!client.connect()) {
        std::cerr << "Failed to connect to NIDS server at "
                  << config.serverAddress << "\n";
        return 1;
    }

    // Dispatch command
    if (command == "status") {
        cmdStatus(client);
    } else if (command == "interfaces") {
        cmdListInterfaces(client);
    } else if (command == "capture" && positionalArgs.size() >= 2) {
        const auto& subcommand = positionalArgs[1];
        auto subArgs = std::vector<std::string>(
            positionalArgs.begin() + 2, positionalArgs.end());

        if (subcommand == "start") {
            cmdCaptureStart(client, subArgs);
        } else if (subcommand == "stop") {
            cmdCaptureStop(client, subArgs);
        } else {
            std::cerr << "Unknown capture subcommand: " << subcommand << "\n";
            return 1;
        }
    } else if (command == "stream") {
        auto subArgs = std::vector<std::string>(
            positionalArgs.begin() + 1, positionalArgs.end());
        cmdStream(client, subArgs);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
