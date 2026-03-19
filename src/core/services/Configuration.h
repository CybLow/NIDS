#pragma once

/// Centralized application configuration (Meyers singleton).
///
/// Provides a single source of truth for all configurable parameters:
/// model paths, timeouts, thresholds, temporary directories. Avoids
/// scattering magic constants across the codebase.
///
/// @par Thread-safety
/// The singleton instance is constructed lazily via C++11 thread-safe
/// static initialization (Meyers singleton).  All **setters** are
/// intended for init-time configuration only — call them during
/// application bootstrap (e.g. in `main()` or `server_main()`) before
/// spawning worker threads.  Once capture or analysis threads start,
/// treat the configuration as **read-only**.  Getters are safe to call
/// concurrently from any thread because the data is effectively immutable
/// after initialization.  If runtime mutation is ever needed, add
/// internal synchronization (e.g. `std::shared_mutex`).

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace nids::core {

/** Centralized application configuration singleton. */
class Configuration {
public:
    /// Access the singleton instance.
    [[nodiscard]] static Configuration& instance();

    // Non-copyable, non-movable (Meyers singleton)
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;

    // -- Model --

    /** Get the path to the ONNX ML model file. */
    [[nodiscard]] const std::filesystem::path& modelPath() const noexcept;
    /** Get the path to the model metadata (normalizer parameters) file. */
    [[nodiscard]] const std::filesystem::path& modelMetadataPath() const noexcept;

    /** Set the path to the ONNX ML model file. */
    void setModelPath(const std::filesystem::path& path);
    /** Set the path to the model metadata file. */
    void setModelMetadataPath(const std::filesystem::path& path);

    // -- Capture --

    /** Get the default pcap dump file path. */
    [[nodiscard]] const std::string& defaultDumpFile() const noexcept;
    /** Get the flow timeout in microseconds. Flows idle beyond this are exported.
     *  Used for batch (post-capture) analysis. Default: 10 minutes. */
    [[nodiscard]] int64_t flowTimeoutUs() const noexcept;
    /** Get the live-mode flow timeout in microseconds.
     *  Used for real-time capture where flows must be delivered promptly.
     *  Default: 60 seconds. */
    [[nodiscard]] int64_t liveFlowTimeoutUs() const noexcept;
    /** Get the maximum flow duration in microseconds for time-window splitting.
     *  Active flows exceeding this age are completed and restarted, ensuring
     *  long-lived connections produce periodic ML verdicts.
     *  Default: 15 seconds (inline IPS mode). */
    [[nodiscard]] int64_t maxFlowDurationUs() const noexcept;
    /** Get the idle threshold in microseconds for flow expiry. */
    [[nodiscard]] int64_t idleThresholdUs() const noexcept;

    /** Set the default pcap dump file path. */
    void setDefaultDumpFile(std::string_view file);
    /** Set the flow timeout in microseconds (batch mode). */
    void setFlowTimeoutUs(int64_t timeoutUs);
    /** Set the live-mode flow timeout in microseconds. */
    void setLiveFlowTimeoutUs(int64_t timeoutUs);
    /** Set the maximum flow duration in microseconds for time-window splitting. */
    void setMaxFlowDurationUs(int64_t durationUs);
    /** Set the idle threshold in microseconds. */
    void setIdleThresholdUs(int64_t thresholdUs);

    // -- Analysis --

    /** Get the platform temporary directory for intermediate files. */
    [[nodiscard]] static std::filesystem::path tempDirectory();
    /** Get the number of ONNX Runtime intra-op parallelism threads. */
    [[nodiscard]] int onnxIntraOpThreads() const noexcept;

    /** Set the number of ONNX Runtime intra-op parallelism threads. */
    void setOnnxIntraOpThreads(int threads);

    // -- Threat Intelligence --

    /** Get the directory containing threat intelligence feed files. */
    [[nodiscard]] const std::filesystem::path& threatIntelDirectory() const noexcept;
    /** Set the directory containing threat intelligence feed files. */
    void setThreatIntelDirectory(const std::filesystem::path& path);

    // -- Hybrid Detection --

    /** Get the ML confidence threshold below which TI/rules take precedence. */
    [[nodiscard]] float mlConfidenceThreshold() const noexcept;
    /** Get the scoring weight for the ML detection layer. */
    [[nodiscard]] float weightMl() const noexcept;
    /** Get the scoring weight for the threat intelligence layer. */
    [[nodiscard]] float weightThreatIntel() const noexcept;
    /** Get the scoring weight for the heuristic rules layer. */
    [[nodiscard]] float weightHeuristic() const noexcept;

    /** Set the ML confidence threshold. */
    void setMlConfidenceThreshold(float threshold);
    /** Set the scoring weight for the ML detection layer. */
    void setWeightMl(float weight);
    /** Set the scoring weight for the threat intelligence layer. */
    void setWeightThreatIntel(float weight);
    /** Set the scoring weight for the heuristic rules layer. */
    void setWeightHeuristic(float weight);

    // -- Output Sinks --

    /** Syslog output sink configuration. */
    struct SyslogOutputConfig {
        bool enabled = false;
        std::string host = "127.0.0.1";
        std::uint16_t port = 514;
        std::string transport = "udp";   ///< "udp", "tcp"
        std::string format = "rfc5424";  ///< "rfc5424", "cef", "leef"
    };

    /** JSON file output sink configuration. */
    struct JsonFileOutputConfig {
        bool enabled = false;
        std::filesystem::path path = "nids_alerts.jsonl";
        std::size_t maxSizeMb = 100;
        int maxFiles = 5;
    };

    [[nodiscard]] const SyslogOutputConfig& syslogOutputConfig() const noexcept;
    [[nodiscard]] const JsonFileOutputConfig& jsonFileOutputConfig() const noexcept;
    [[nodiscard]] bool consoleOutputEnabled() const noexcept;

    void setSyslogOutputConfig(const SyslogOutputConfig& config);
    void setJsonFileOutputConfig(const JsonFileOutputConfig& config);
    void setConsoleOutputEnabled(bool enabled);

    // -- Threat Hunting --

    /** PCAP ring-buffer storage configuration. */
    struct PcapStorageConfig {
        std::filesystem::path storageDir = "data/pcap";
        std::size_t maxTotalSizeBytes = 10ULL * 1024 * 1024 * 1024;  ///< 10 GB
        int64_t maxRetentionHours = 168;                              ///< 7 days
        std::size_t maxFileSizeBytes = 100 * 1024 * 1024;             ///< 100 MB
        std::string filePrefix = "nids_capture";
    };

    /** Threat hunting subsystem configuration. */
    struct HuntingConfig {
        bool enabled = false;
        PcapStorageConfig pcapStorage;
        std::filesystem::path flowDatabasePath = "data/flows.db";
        std::size_t maxDatabaseSizeMb = 1024;   ///< 1 GB
        bool indexAllFlows = true;               ///< false = only flagged flows
        int baselineWindowHours = 168;           ///< 7 days
        double anomalyThresholdSigma = 3.0;      ///< 3-sigma anomaly threshold
    };

    [[nodiscard]] const HuntingConfig& huntingConfig() const noexcept;
    void setHuntingConfig(const HuntingConfig& config);

    // -- YARA Content Scanning --

    /** YARA content scanning configuration. */
    struct YaraConfig {
        bool enabled = false;
        std::filesystem::path rulesDirectory = "data/yara";
        bool scanPackets = true;         ///< Per-packet quick scan
        bool scanStreams = true;         ///< Per-stream deep scan (TCP reassembly)
        int scanTimeoutMs = 10;          ///< Per-scan timeout in milliseconds
        std::size_t maxStreamSizeBytes = 1 * 1024 * 1024;  ///< 1 MB
        std::size_t maxConcurrentStreams = 10000;
        bool hotReload = true;           ///< Watch rules dir for changes
        float weight = 0.10f;            ///< Scoring weight in hybrid detection
    };

    [[nodiscard]] const YaraConfig& yaraConfig() const noexcept;
    void setYaraConfig(const YaraConfig& config);

    // -- Snort Signature Detection --

    /** Snort signature engine configuration. */
    struct SignatureConfig {
        bool enabled = false;
        std::filesystem::path rulesDirectory = "data/rules";
        bool hotReload = true;
        int maxPcreMatchLength = 1500;
        std::string homeNet = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"; // NOSONAR — RFC 1918 defaults, user-configurable
        std::string externalNet = "!$HOME_NET";
        std::string httpPorts = "80,443,8080,8443";
        float weight = 0.25f;  ///< Scoring weight in hybrid detection
    };

    [[nodiscard]] const SignatureConfig& signatureConfig() const noexcept;
    void setSignatureConfig(const SignatureConfig& config);

    // -- UI --

    /** Get the main window title string. */
    [[nodiscard]] const std::string& windowTitle() const noexcept;
    /** Set the main window title string. */
    void setWindowTitle(std::string_view title);

private:
    Configuration();

    std::filesystem::path modelPath_{"models/model.onnx"};
    std::filesystem::path metadataPath_{"models/model_metadata.json"};
    std::filesystem::path threatIntelDir_{"data/threat_intel"};
    std::string defaultDumpFile_{"dump.pcap"};
    int64_t flowTimeoutUs_ = 600'000'000;       // 10 minutes (batch)
    int64_t liveFlowTimeoutUs_ = 60'000'000;    // 60 seconds (live capture)
    int64_t maxFlowDurationUs_ = 15'000'000;    // 15 seconds (time-window split)
    int64_t idleThresholdUs_ = 5'000'000;       // 5 seconds
    int onnxIntraOpThreads_ = 1;
    float mlConfidenceThreshold_ = 0.7f;
    float weightMl_ = 0.5f;
    float weightThreatIntel_ = 0.3f;
    float weightHeuristic_ = 0.2f;
    std::string windowTitle_{"NIDS - Network Intrusion Detection System"};
    SyslogOutputConfig syslogOutputConfig_;
    JsonFileOutputConfig jsonFileOutputConfig_;
    bool consoleOutputEnabled_ = true;
    HuntingConfig huntingConfig_;
    YaraConfig yaraConfig_;
    SignatureConfig signatureConfig_;
};

} // namespace nids::core
