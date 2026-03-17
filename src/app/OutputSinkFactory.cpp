#include "app/OutputSinkFactory.h"

#include "core/services/Configuration.h"
#include "infra/output/ConsoleAlertSink.h"
#include "infra/output/JsonFileSink.h"
#include "infra/output/SyslogSink.h"

#include <spdlog/spdlog.h>

namespace nids::app {

std::unique_ptr<SinkChain> OutputSinkFactory::createFromConfig(
    const core::Configuration& config) {

    auto chain = std::make_unique<SinkChain>();

    // -- Console sink (enabled by default) --
    if (config.consoleOutputEnabled()) {
        chain->addSink(
            std::make_unique<infra::ConsoleAlertSink>(infra::ConsoleFilter::Flagged));
        spdlog::debug("OutputSinkFactory: added ConsoleAlertSink");
    }

    // -- Syslog sink --
    const auto& syslogCfg = config.syslogOutputConfig();
    if (syslogCfg.enabled) {
        infra::SyslogConfig sc;
        sc.host = syslogCfg.host;
        sc.port = syslogCfg.port;

        // Parse transport
        if (syslogCfg.transport == "tcp") {
            sc.transport = infra::SyslogTransport::Tcp;
        } else {
            sc.transport = infra::SyslogTransport::Udp;
        }

        // Parse format
        if (syslogCfg.format == "cef") {
            sc.format = infra::SyslogFormat::Cef;
        } else if (syslogCfg.format == "leef") {
            sc.format = infra::SyslogFormat::Leef;
        } else {
            sc.format = infra::SyslogFormat::Rfc5424;
        }

        chain->addSink(std::make_unique<infra::SyslogSink>(std::move(sc)));
        spdlog::debug("OutputSinkFactory: added SyslogSink ({}:{}, {})",
                      syslogCfg.host, syslogCfg.port, syslogCfg.format);
    }

    // -- JSON file sink --
    const auto& jsonCfg = config.jsonFileOutputConfig();
    if (jsonCfg.enabled) {
        infra::JsonFileConfig jc;
        jc.outputPath = jsonCfg.path;
        jc.maxFileSizeBytes = jsonCfg.maxSizeMb * 1024 * 1024;
        jc.maxFiles = jsonCfg.maxFiles;

        chain->addSink(std::make_unique<infra::JsonFileSink>(std::move(jc)));
        spdlog::debug("OutputSinkFactory: added JsonFileSink ({})",
                      jsonCfg.path.string());
    }

    spdlog::info("OutputSinkFactory: created chain with {} sinks",
                 chain->sinkCount());
    return chain;
}

} // namespace nids::app
