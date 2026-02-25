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

    // -- Capture --

    [[nodiscard]] std::string defaultDumpFile() const;
    [[nodiscard]] int64_t flowTimeoutUs() const;
    [[nodiscard]] int64_t idleThresholdUs() const;

    // -- Analysis --

    [[nodiscard]] std::filesystem::path tempDirectory() const;
    [[nodiscard]] int onnxIntraOpThreads() const;

    // -- UI --

    [[nodiscard]] std::string windowTitle() const;

    /// Load overrides from a JSON config file (optional).
    /// Returns false if the file exists but cannot be parsed.
    [[nodiscard]] bool loadFromFile(const std::filesystem::path& configPath);

private:
    Configuration();

    // Non-copyable, non-movable
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;

    std::filesystem::path modelPath_;
    std::filesystem::path metadataPath_;
    std::string defaultDumpFile_;
    int64_t flowTimeoutUs_;
    int64_t idleThresholdUs_;
    int onnxIntraOpThreads_;
    std::string windowTitle_;
};

} // namespace nids::core
