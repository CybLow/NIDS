#pragma once

/// JSON-lines (JSONL) file output sink.
///
/// Writes one JSON object per flow to a file for offline analysis, archival,
/// or ingestion by log shippers (Filebeat, Fluentd, Logstash).
///
/// Supports:
///   - Append or truncate mode
///   - Automatic file rotation when a size threshold is reached
///   - Configurable number of rotated file backups

#include "core/services/IOutputSink.h"

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace nids::infra {

/// Configuration for JsonFileSink.
struct JsonFileConfig {
    std::filesystem::path outputPath = "nids_alerts.jsonl";
    bool appendMode = true;                          ///< Append to existing file
    std::size_t maxFileSizeBytes = 100 * 1024 * 1024; ///< 100 MB rotation threshold
    int maxFiles = 5;                                ///< Rotated backups to keep
};

class JsonFileSink final : public core::IOutputSink {
public:
    explicit JsonFileSink(JsonFileConfig config);
    ~JsonFileSink() override;

    // Non-copyable
    JsonFileSink(const JsonFileSink&) = delete;
    JsonFileSink& operator=(const JsonFileSink&) = delete;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "JsonFileSink";
    }

    [[nodiscard]] bool start() override;
    void onFlowResult(std::size_t flowIndex,
                      const core::DetectionResult& result,
                      const core::FlowInfo& flow) override;
    void stop() override;

    /// Format a detection result as a compact JSON string (for testing).
    [[nodiscard]] static std::string toJson(
        std::size_t flowIndex,
        const core::DetectionResult& result,
        const core::FlowInfo& flow);

private:
    /// Rotate the file if it exceeds the configured size threshold.
    void rotateIfNeeded();

    JsonFileConfig config_;
    std::ofstream file_;
    std::size_t currentSize_ = 0;
    std::mutex fileMutex_;
    std::atomic<std::size_t> linesWritten_{0};
    std::atomic<std::size_t> writeErrors_{0};
};

} // namespace nids::infra
