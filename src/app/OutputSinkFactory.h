#pragma once

/// Factory for creating a configured SinkChain from application configuration.
///
/// Reads the output section of Configuration and instantiates enabled sinks
/// (SyslogSink, JsonFileSink, ConsoleAlertSink). Returns a ready-to-use
/// SinkChain that can be registered on LiveDetectionPipeline.

#include "app/SinkChain.h"

#include <memory>

namespace nids::core {
class Configuration;
}

namespace nids::app {

class OutputSinkFactory {
public:
    /// Create a SinkChain populated with sinks based on current configuration.
    ///
    /// If no output sinks are enabled, returns an empty SinkChain (zero sinks).
    [[nodiscard]] static std::unique_ptr<SinkChain> createFromConfig(
        const core::Configuration& config);
};

} // namespace nids::app
