#include "app/SetupWizard.h"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#ifdef __linux__
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace nids::app {

namespace fs = std::filesystem;

bool SetupWizard::isSetupNeeded(const fs::path& configPath) {
    return !fs::exists(configPath);
}

// ── Interactive prompts ─────────────────────────────────────────────

std::string SetupWizard::askString(const std::string& prompt,
                                    const std::string& defaultVal) const {
    std::cout << prompt;
    if (!defaultVal.empty()) std::cout << " [" << defaultVal << "]";
    std::cout << ": ";

    std::string input;
    std::getline(std::cin, input);
    return input.empty() ? defaultVal : input;
}

bool SetupWizard::askYesNo(const std::string& prompt, bool defaultVal) const {
    std::cout << prompt << (defaultVal ? " [Y/n]: " : " [y/N]: ");
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) return defaultVal;
    return input[0] == 'y' || input[0] == 'Y';
}

// ── Setup steps ─────────────────────────────────────────────────────

fs::path SetupWizard::run() {
    std::cout << "\n"
              << "╔══════════════════════════════════════════╗\n"
              << "║   NIDS — First-Run Setup Wizard         ║\n"
              << "╚══════════════════════════════════════════╝\n\n"
              << "No configuration found. Let's set up NIDS.\n\n";

    stepInterface();
    stepDetection();
    stepOutput();
    stepRules();
    stepFinalize();

    return configPath_;
}

void SetupWizard::stepInterface() {
    std::cout << "── Step 1: Network Interface ──\n\n";
    interface_ = askString("Capture interface (e.g., eth0, wlan0)", "eth0");
    std::cout << "\n";
}

void SetupWizard::stepDetection() {
    std::cout << "── Step 2: Detection Engines ──\n\n";
    enableMl_ = askYesNo("Enable ML classifier (ONNX model)?", true);
    enableThreatIntel_ = askYesNo("Enable threat intelligence feeds?", true);
    enableSignatures_ = askYesNo("Enable Snort/Suricata signature rules?", true);
    enableYara_ = askYesNo("Enable YARA content scanning?", false);
    std::cout << "\n";
}

void SetupWizard::stepOutput() {
    std::cout << "── Step 3: Output Sinks ──\n\n";
    enableSyslog_ = askYesNo("Enable Syslog output (CEF/LEEF)?", false);
    if (enableSyslog_) {
        syslogHost_ = askString("Syslog host", "localhost");
        auto portStr = askString("Syslog port", "514");
        syslogPort_ = std::stoi(portStr);
    }
    enableJsonLog_ = askYesNo("Enable JSON file logging?", true);
    if (enableJsonLog_) {
        jsonLogPath_ = askString("JSON log path", "data/alerts.jsonl");
    }
    std::cout << "\n";
}

void SetupWizard::stepRules() {
    std::cout << "── Step 4: Community Rules ──\n\n";
    downloadRules_ = askYesNo(
        "Download Emerging Threats Open rules + abuse.ch feeds?", true);
    if (downloadRules_) {
        downloadRulesAndFeeds();
    }
    std::cout << "\n";
}

void SetupWizard::stepFinalize() {
    std::cout << "── Step 5: Save Configuration ──\n\n";
    auto path = askString("Config file path", "config.json");
    configPath_ = path;
    writeConfig(configPath_);
    std::cout << "\nConfiguration saved to: " << configPath_ << "\n";
    std::cout << "Run nids-server with: nids-server --config "
              << configPath_ << " --interface " << interface_ << "\n\n";
}

// ── Rule/feed download ──────────────────────────────────────────────

void SetupWizard::downloadRulesAndFeeds() const {
    std::cout << "\nDownloading community rules and threat intel feeds...\n";

    // Find the download script.
    for (const auto& dir : {".", "..", "scripts/ops", "/opt/nids/scripts"}) {
        auto script = fs::path(dir) / "download_rules.sh";
        if (!fs::exists(script)) continue;

#ifdef __linux__
        // Use fork/exec instead of banned system().
        pid_t pid = ::fork();
        if (pid == 0) {
            auto path = script.string();
            char* argv[] = {path.data(), nullptr};
            ::execvp(path.c_str(), argv);
            ::_exit(127); // exec failed
        } else if (pid > 0) {
            int status = 0;
            ::waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                std::cout << "Download complete.\n";
            } else {
                std::cout << "Download script failed (some downloads "
                             "may have failed).\n";
            }
        }
#else
        std::cout << "Automatic download not available on this platform.\n"
                  << "Run manually: " << script.string() << "\n";
#endif
        return;
    }

    std::cout << "Download script not found. Run manually:\n"
              << "  ./scripts/ops/download_rules.sh\n";
}

// ── Config generation ───────────────────────────────────────────────

void SetupWizard::writeConfig(const fs::path& path) const {
    nlohmann::json config;

    // Model.
    config["model"]["path"] = "models/model.onnx";
    config["model"]["metadata_path"] = "models/model_metadata.json";

    // Hybrid detection.
    config["hybrid_detection"]["weight_ml"] = 0.35;
    config["hybrid_detection"]["weight_threat_intel"] = 0.20;
    config["hybrid_detection"]["weight_heuristic"] = 0.10;

    // Output.
    config["output"]["console"]["enabled"] = true;

    if (enableSyslog_) {
        config["output"]["syslog"]["enabled"] = true;
        config["output"]["syslog"]["host"] = syslogHost_;
        config["output"]["syslog"]["port"] = syslogPort_;
        config["output"]["syslog"]["format"] = "cef";
    }

    if (enableJsonLog_) {
        config["output"]["json_file"]["enabled"] = true;
        config["output"]["json_file"]["path"] = jsonLogPath_;
        config["output"]["json_file"]["max_size_mb"] = 100;
        config["output"]["json_file"]["max_files"] = 10;
    }

    // Threat hunting.
    if (enableThreatIntel_) {
        config["hunting"]["enabled"] = true;
        config["hunting"]["flow_database_path"] = "data/flows.db";
    }

    // Signatures.
    if (enableSignatures_) {
        config["signatures"]["enabled"] = true;
        config["signatures"]["rules_directory"] = "data/rules";
    }

    // YARA.
    if (enableYara_) {
        config["yara"]["enabled"] = true;
        config["yara"]["rules_directory"] = "data/yara";
    }

    // Write.
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }
    std::ofstream out(path);
    out << config.dump(4) << "\n";
}

} // namespace nids::app
