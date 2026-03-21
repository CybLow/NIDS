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

#include "infra/platform/AsanOptions.h" // shared gRPC ASan workaround

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
        << "  health                              Health check\n"
        << "  interfaces                          List network interfaces\n"
        << "  capture start <iface> [--bpf <f>]   Start capture\n"
        << "  capture stop [session-id]            Stop capture\n"
        << "  stream [--filter flagged|clean|all]  Stream detections\n"
        << "  search --ip <ip> [--flagged]         Search flow database\n"
        << "  ioc <ip1> [<ip2> ...]               IOC indicator search\n"
        << "  rules load <path>                   Load Snort/YARA rules\n"
        << "  rules stats                         Show rule statistics\n"
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
    nids::DetectionFilter filter = nids::FILTER_ALL;

    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--filter" && i + 1 < args.size()) {
            const auto& val = args[++i];
            if (val == "flagged") {
                filter = nids::FILTER_FLAGGED;
            } else if (val == "clean") {
                filter = nids::FILTER_CLEAN;
            } else if (val == "all") {
                filter = nids::FILTER_ALL;
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
        [](const nids::DetectionEvent& event) {
            const char* verdict =
                event.verdict() == nids::VERDICT_ATTACK ? "ATTACK" :
                event.verdict() == nids::VERDICT_BENIGN ? "BENIGN" :
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

void cmdHealth(nids::client::NidsClient& client) {
    auto info = client.healthCheck();
    std::cout << "Health Check:\n"
              << "  Healthy:     " << (info.healthy ? "yes" : "no") << "\n"
              << "  Version:     " << info.version << "\n"
              << "  Uptime:      " << info.uptimeSeconds << "s\n"
              << "  Total flows: " << info.totalFlows << "\n"
              << "  Total alerts:" << info.totalAlerts << "\n";
}

void cmdSearch(nids::client::NidsClient& client,
               const std::vector<std::string>& args) {
    nids::SearchFlowsRequest request;
    bool flaggedOnly = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--ip" && i + 1 < args.size()) {
            request.set_any_ip(args[++i]);
        } else if (args[i] == "--flagged") {
            flaggedOnly = true;
        } else if (args[i] == "--limit" && i + 1 < args.size()) {
            request.set_limit(static_cast<std::uint32_t>(std::stoul(args[++i])));
        }
    }
    request.set_flagged_only(flaggedOnly);
    if (request.limit() == 0) request.set_limit(20);

    auto response = client.searchFlows(request);

    std::cout << "Found " << response.total_count() << " flows:\n\n";
    for (const auto& f : response.flows()) {
        std::cout << "  " << f.src_ip() << ":" << f.src_port()
                  << " -> " << f.dst_ip() << ":" << f.dst_port()
                  << "  " << f.verdict()
                  << "  score=" << std::fixed << std::setprecision(2)
                  << f.combined_score()
                  << (f.is_flagged() ? " [FLAGGED]" : "") << "\n";
    }
}

void cmdIocSearch(nids::client::NidsClient& client,
                  const std::vector<std::string>& args) {
    nids::IocSearchRequest request;
    for (const auto& ip : args) {
        request.add_ips(ip);
    }

    auto response = client.iocSearch(request);

    std::cout << "IOC Search: scanned " << response.total_scanned()
              << " flows, " << response.matched_flows_size()
              << " matches:\n\n";
    for (const auto& f : response.matched_flows()) {
        std::cout << "  " << f.src_ip() << ":" << f.src_port()
                  << " -> " << f.dst_ip() << ":" << f.dst_port()
                  << "  " << f.verdict()
                  << (f.is_flagged() ? " [FLAGGED]" : "") << "\n";
    }
}

void cmdRulesLoad(nids::client::NidsClient& client,
                  const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: path required\n";
        return;
    }
    auto response = client.loadRules(args[0]);
    std::cout << (response.success() ? "Success" : "Failed")
              << ": " << response.message()
              << " (" << response.rules_loaded() << " rules)\n";
}

void cmdRulesStats(nids::client::NidsClient& client) {
    auto response = client.getRuleStats();
    std::cout << "Rule Statistics:\n"
              << "  Snort rules: " << response.total_rules()
              << " (" << response.rule_files() << " files)\n"
              << "  YARA rules:  " << response.yara_rules()
              << " (" << response.yara_files() << " files)\n";
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
    } else if (command == "health") {
        cmdHealth(client);
    } else if (command == "search") {
        auto subArgs = std::vector<std::string>(
            positionalArgs.begin() + 1, positionalArgs.end());
        cmdSearch(client, subArgs);
    } else if (command == "ioc") {
        auto subArgs = std::vector<std::string>(
            positionalArgs.begin() + 1, positionalArgs.end());
        cmdIocSearch(client, subArgs);
    } else if (command == "rules" && positionalArgs.size() >= 2) {
        const auto& sub = positionalArgs[1];
        auto subArgs = std::vector<std::string>(
            positionalArgs.begin() + 2, positionalArgs.end());
        if (sub == "load") {
            cmdRulesLoad(client, subArgs);
        } else if (sub == "stats") {
            cmdRulesStats(client);
        } else {
            std::cerr << "Unknown rules subcommand: " << sub << "\n";
            return 1;
        }
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
