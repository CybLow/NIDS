#pragma once

/// SetupWizard — interactive first-run configuration for nids-server/cli.
///
/// When no config.json exists, guides the user through selecting a
/// network interface, enabling features, downloading community rules
/// and threat intel feeds, and generating the configuration file.

#include <filesystem>
#include <string>
#include <vector>

namespace nids::app {

class SetupWizard {
public:
    /// Run the interactive setup. Returns the generated config path.
    [[nodiscard]] std::filesystem::path run();

    /// Check if setup is needed (no config file at default/given path).
    [[nodiscard]] static bool isSetupNeeded(
        const std::filesystem::path& configPath);

private:
    std::string askString(const std::string& prompt,
                           const std::string& defaultVal) const;
    bool askYesNo(const std::string& prompt, bool defaultVal) const;
    int askChoice(const std::string& prompt,
                  const std::vector<std::string>& options) const;

    void stepInterface();
    void stepDetection();
    void stepOutput();
    void stepRules();
    void stepFinalize();

    /// Download rules and feeds.
    void downloadRulesAndFeeds() const;

    /// Generate config.json from collected settings.
    void writeConfig(const std::filesystem::path& path) const;

    // Collected settings.
    std::string interface_;
    bool enableMl_ = true;
    bool enableThreatIntel_ = true;
    bool enableSignatures_ = false;
    bool enableYara_ = false;
    bool enableSyslog_ = false;
    std::string syslogHost_ = "localhost";
    int syslogPort_ = 514;
    bool enableJsonLog_ = true;
    std::string jsonLogPath_ = "data/alerts.jsonl";
    bool downloadRules_ = true;
    std::filesystem::path configPath_ = "config.json";
};

} // namespace nids::app
