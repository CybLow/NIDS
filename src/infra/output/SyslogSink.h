#pragma once

/// Syslog output sink — forwards detection results via syslog (RFC 5424).
///
/// Supports UDP and TCP transport.  The message body can be formatted as
/// plain RFC 5424 structured data, CEF (Common Event Format), or LEEF.
///
/// The sink opens a socket on start() and closes it on stop().
/// Thread-safe: onFlowResult() is called from the FlowAnalysisWorker thread.

#include "core/services/IOutputSink.h"
#include "infra/output/CefFormatter.h"
#include "infra/output/LeefFormatter.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace nids::infra {

/// Syslog transport protocol.
enum class SyslogTransport : std::uint8_t { Udp, Tcp };

/// Syslog message body format.
enum class SyslogFormat : std::uint8_t {
    Rfc5424,    ///< RFC 5424 structured data
    Cef,        ///< ArcSight Common Event Format
    Leef        ///< IBM QRadar LEEF
};

/// Configuration for SyslogSink.
struct SyslogConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 514;
    SyslogTransport transport = SyslogTransport::Udp;
    SyslogFormat format = SyslogFormat::Rfc5424;
    std::string appName = "nids";
    std::string hostname;   ///< Auto-detected from system if empty.
    int facility = 16;      ///< LOG_LOCAL0 = 16 (local use 0)
};

class SyslogSink final : public core::IOutputSink {
public:
    explicit SyslogSink(SyslogConfig config);
    ~SyslogSink() override;

    // Non-copyable
    SyslogSink(const SyslogSink&) = delete;
    SyslogSink& operator=(const SyslogSink&) = delete;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "SyslogSink";
    }

    [[nodiscard]] bool start() override;
    void onFlowResult(std::size_t flowIndex,
                      const core::DetectionResult& result,
                      const core::FlowInfo& flow) override;
    void stop() override;

    /// Format a message without sending (for testing).
    [[nodiscard]] std::string formatMessage(
        std::size_t flowIndex,
        const core::DetectionResult& result,
        const core::FlowInfo& flow) const;

private:
    /// Map combinedScore to syslog severity (0=emergency .. 7=debug).
    [[nodiscard]] static int syslogSeverity(float combinedScore) noexcept;

    /// Build RFC 5424 structured data message.
    [[nodiscard]] std::string formatRfc5424(
        std::size_t flowIndex,
        const core::DetectionResult& result,
        const core::FlowInfo& flow) const;

    /// Send a message via the configured transport.
    void sendMessage(std::string_view message);

    /// Resolve hostname if not configured.
    void resolveHostname();

    SyslogConfig config_;
    int socket_ = -1;
    std::mutex socketMutex_;
    std::atomic<std::size_t> messagesSent_{0};
    std::atomic<std::size_t> sendErrors_{0};

    CefFormatter cefFormatter_;
    LeefFormatter leefFormatter_;
};

} // namespace nids::infra
