#pragma once

/// Centralized application configuration (Meyers singleton).
///
/// Provides a single source of truth for all configurable parameters:
/// model paths, timeouts, thresholds, temporary directories. Avoids
/// scattering magic constants across the codebase.
///
/// Thread-safe via C++11 static initialization guarantees.

#include <filesystem>
#include <string>
#include <cstdint>

namespace nids::core {

class Configuration {
public:
    /// Access the singleton instance.
    [[nodiscard]] static Configuration& instance();

    // -- Model --

    [[nodiscard]] std::filesystem::path modelPath() const;
    [[nodiscard]] std::filesystem::path modelMetadataPath() const;

    void setModelPath(const std::filesystem::path& path);
    void setModelMetadataPath(const std::filesystem::path& path);

    // -- Capture --

    [[nodiscard]] std::string defaultDumpFile() const;
    [[nodiscard]] int64_t flowTimeoutUs() const;
    [[nodiscard]] int64_t idleThresholdUs() const;

    void setDefaultDumpFile(const std::string& file);
    void setFlowTimeoutUs(int64_t timeoutUs);
    void setIdleThresholdUs(int64_t thresholdUs);

    // -- Analysis --

    [[nodiscard]] std::filesystem::path tempDirectory() const;
    [[nodiscard]] int onnxIntraOpThreads() const;

    void setOnnxIntraOpThreads(int threads);

    // -- Threat Intelligence --

    [[nodiscard]] std::filesystem::path threatIntelDirectory() const;
    void setThreatIntelDirectory(const std::filesystem::path& path);

    // -- Hybrid Detection --

    [[nodiscard]] float mlConfidenceThreshold() const noexcept;
    [[nodiscard]] float weightMl() const noexcept;
    [[nodiscard]] float weightThreatIntel() const noexcept;
    [[nodiscard]] float weightHeuristic() const noexcept;

    void setMlConfidenceThreshold(float threshold);
    void setWeightMl(float weight);
    void setWeightThreatIntel(float weight);
    void setWeightHeuristic(float weight);

    // -- UI --

    [[nodiscard]] std::string windowTitle() const;
    void setWindowTitle(const std::string& title);

private:
    Configuration();

    // Non-copyable, non-movable
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;

    std::filesystem::path modelPath_;
    std::filesystem::path metadataPath_;
    std::filesystem::path threatIntelDir_;
    std::string defaultDumpFile_;
    int64_t flowTimeoutUs_;
    int64_t idleThresholdUs_;
    int onnxIntraOpThreads_;
    float mlConfidenceThreshold_;
    float weightMl_;
    float weightThreatIntel_;
    float weightHeuristic_;
    std::string windowTitle_;
};

} // namespace nids::core
