#include "app/OutputSinkFactory.h"

#include "core/services/Configuration.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

using namespace nids;

namespace {

/// Reset output-related configuration to a known state.
void resetOutputConfig(core::Configuration& cfg) {
    core::Configuration::SyslogOutputConfig sc;
    sc.enabled = false;
    cfg.setSyslogOutputConfig(sc);

    core::Configuration::JsonFileOutputConfig jc;
    jc.enabled = false;
    cfg.setJsonFileOutputConfig(jc);

    cfg.setConsoleOutputEnabled(false);
}

} // namespace

TEST(OutputSinkFactory, createFromConfig_allDisabled_returnsEmptyChain) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 0u);
}

TEST(OutputSinkFactory, createFromConfig_consoleOnly_returnsOneSink) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);
    cfg.setConsoleOutputEnabled(true);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 1u);
}

TEST(OutputSinkFactory, createFromConfig_syslogUdpRfc5424_returnsOneSink) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    core::Configuration::SyslogOutputConfig sc;
    sc.enabled = true;
    sc.host = "127.0.0.1";
    sc.port = 514;
    sc.transport = "udp";
    sc.format = "rfc5424";
    cfg.setSyslogOutputConfig(sc);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 1u);
}

TEST(OutputSinkFactory, createFromConfig_syslogTcpCef_returnsOneSink) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    core::Configuration::SyslogOutputConfig sc;
    sc.enabled = true;
    sc.host = "localhost";
    sc.port = 1514;
    sc.transport = "tcp";
    sc.format = "cef";
    cfg.setSyslogOutputConfig(sc);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 1u);
}

TEST(OutputSinkFactory, createFromConfig_syslogLeef_returnsOneSink) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    core::Configuration::SyslogOutputConfig sc;
    sc.enabled = true;
    sc.format = "leef";
    cfg.setSyslogOutputConfig(sc);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 1u);
}

TEST(OutputSinkFactory, createFromConfig_jsonFileEnabled_returnsOneSink) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    core::Configuration::JsonFileOutputConfig jc;
    jc.enabled = true;
    jc.path = "/tmp/nids_test_factory_out.jsonl";
    jc.maxSizeMb = 10;
    jc.maxFiles = 3;
    cfg.setJsonFileOutputConfig(jc);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 1u);
}

TEST(OutputSinkFactory, createFromConfig_allEnabled_returnsThreeSinks) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);
    cfg.setConsoleOutputEnabled(true);

    core::Configuration::SyslogOutputConfig sc;
    sc.enabled = true;
    cfg.setSyslogOutputConfig(sc);

    core::Configuration::JsonFileOutputConfig jc;
    jc.enabled = true;
    jc.path = "/tmp/nids_test_factory_all.jsonl";
    cfg.setJsonFileOutputConfig(jc);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->sinkCount(), 3u);
}

TEST(OutputSinkFactory, createFromConfig_returnsNamedSinkChain) {
    auto& cfg = core::Configuration::instance();
    resetOutputConfig(cfg);

    auto chain = app::OutputSinkFactory::createFromConfig(cfg);

    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->name(), "SinkChain");
}
