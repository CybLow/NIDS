#include "infra/output/SyslogSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>

namespace nids::infra {

namespace {

/// Close a socket handle in a platform-portable way.
void closeSocket(SocketHandle s) {
#ifdef _WIN32
  ::closesocket(s);
#else
  ::close(s);
#endif
}

/// Return a human-readable error string for the last socket operation.
[[nodiscard]] std::string socketErrorString() {
#ifdef _WIN32
  const int err = WSAGetLastError();
  char buf[256]{};
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, static_cast<DWORD>(err),
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf),
                 nullptr);
  return std::string(buf);
#else
  return std::strerror(errno);
#endif
}

} // anonymous namespace

SyslogSink::SyslogSink(SyslogConfig config) : config_(std::move(config)) {}

SyslogSink::~SyslogSink() {
  try {
    stop();
  } catch (const std::exception &e) {
    spdlog::error("SyslogSink: exception in destructor: {}", e.what());
  }
}

bool SyslogSink::start() {
  messagesSent_.store(0);
  sendErrors_.store(0);
  resolveHostname();

  const int type =
      (config_.transport == SyslogTransport::Tcp) ? SOCK_STREAM : SOCK_DGRAM;

  socket_ = ::socket(AF_INET, type, 0);
  if (socket_ == kInvalidSocket) {
    spdlog::error("SyslogSink: socket() failed: {}", socketErrorString());
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(config_.port);

  if (::inet_pton(AF_INET, config_.host.c_str(), &addr.sin_addr) != 1) {
    // Try DNS resolution
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = type;
    addrinfo *res = nullptr;
    if (::getaddrinfo(config_.host.c_str(), nullptr, &hints, &res) != 0 ||
        res == nullptr) {
      spdlog::error("SyslogSink: cannot resolve host '{}'", config_.host);
      closeSocket(socket_);
      socket_ = kInvalidSocket;
      return false;
    }
    const auto *resolved =
        reinterpret_cast<const sockaddr_in *>(res->ai_addr); // NOLINT
    addr.sin_addr = resolved->sin_addr;
    ::freeaddrinfo(res);
  }

  if (config_.transport == SyslogTransport::Tcp) {
    if (::connect(socket_, reinterpret_cast<sockaddr *>(&addr), // NOLINT
                  sizeof(addr)) < 0) {
      spdlog::error("SyslogSink: connect() to {}:{} failed: {}", config_.host,
                    config_.port, socketErrorString());
      closeSocket(socket_);
      socket_ = kInvalidSocket;
      return false;
    }
  } else {
    // For UDP, connect() sets the default destination.
    ::connect(socket_, reinterpret_cast<sockaddr *>(&addr), // NOLINT
              sizeof(addr));
  }

  spdlog::info("SyslogSink started: {}:{} ({})", config_.host, config_.port,
               config_.transport == SyslogTransport::Tcp ? "TCP" : "UDP");
  return true;
}

void SyslogSink::onFlowResult(std::size_t flowIndex,
                              const core::DetectionResult &result,
                              const core::FlowInfo &flow) {
  auto msg = formatMessage(flowIndex, result, flow);
  sendMessage(msg);
}

void SyslogSink::stop() {
  if (socket_ != kInvalidSocket) {
    spdlog::info("SyslogSink stopped: {} messages sent, {} errors",
                 messagesSent_.load(), sendErrors_.load());
    closeSocket(socket_);
    socket_ = kInvalidSocket;
  }
}

std::string SyslogSink::formatMessage(std::size_t flowIndex,
                                      const core::DetectionResult &result,
                                      const core::FlowInfo &flow) const {

  using enum SyslogFormat;
  switch (config_.format) {
  case Cef:
    return cefFormatter_.format(flowIndex, result, flow);
  case Leef:
    return leefFormatter_.format(flowIndex, result, flow);
  case Rfc5424:
  default:
    return formatRfc5424(flowIndex, result, flow);
  }
}

std::string SyslogSink::formatRfc5424(std::size_t flowIndex,
                                      const core::DetectionResult &result,
                                      const core::FlowInfo &flow) const {

  const int severity = syslogSeverity(result.combinedScore);
  const int pri = config_.facility * 8 + severity;

  const auto now = std::chrono::system_clock::now();
  const auto timestamp =
      fmt::format("{:%Y-%m-%dT%H:%M:%S}Z",
                  fmt::gmtime(std::chrono::system_clock::to_time_t(now)));

  const auto verdictStr =
      std::string{core::attackTypeToString(result.finalVerdict)};
  const auto sourceStr =
      std::string{core::detectionSourceToString(result.detectionSource)};

  // Build TI matches string
  std::string tiFeeds;
  for (const auto &m : result.threatIntelMatches) {
    if (!tiFeeds.empty())
      tiFeeds += ',';
    tiFeeds += m.feedName;
  }

  // Build rule matches string
  std::string rules;
  for (const auto &r : result.ruleMatches) {
    if (!rules.empty())
      rules += ',';
    rules += r.ruleName;
  }

  // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
  return fmt::format(R"(<{}>1 {} {} {} - - )"
                     R"([nids@49999 )"
                     R"(srcIp="{}" dstIp="{}" srcPort="{}" dstPort="{}" )"
                     R"(protocol="{}" verdict="{}" confidence="{:.4f}" )"
                     R"(combinedScore="{:.4f}" detectionSource="{}" )"
                     R"(tiMatches="{}" ruleMatches="{}"] )"
                     R"(flow #{}: {} (confidence {:.1f}%))",
                     pri, timestamp, config_.hostname, config_.appName,
                     flow.srcIp, flow.dstIp, flow.srcPort, flow.dstPort,
                     core::protocolToName(flow.protocol), verdictStr,
                     result.mlResult.confidence, result.combinedScore,
                     sourceStr, tiFeeds, rules, flowIndex, verdictStr,
                     result.mlResult.confidence * 100.0f);
}

int SyslogSink::syslogSeverity(float combinedScore) noexcept {
  // Map combinedScore to RFC 5424 severity:
  //   0 = Emergency, 1 = Alert, 2 = Critical, 3 = Error,
  //   4 = Warning, 5 = Notice, 6 = Informational, 7 = Debug
  if (combinedScore >= 0.85f)
    return 2; // Critical
  if (combinedScore >= 0.7f)
    return 3; // Error
  if (combinedScore >= 0.5f)
    return 4; // Warning
  if (combinedScore >= 0.3f)
    return 5; // Notice
  return 6;   // Informational
}

void SyslogSink::sendMessage(std::string_view message) {
  if (socket_ == kInvalidSocket)
    return;

  std::scoped_lock lock{socketMutex_};
#ifdef _WIN32
  const auto sent =
      ::send(socket_, message.data(), static_cast<int>(message.size()), 0);
#else
  const auto sent = ::send(socket_, message.data(), message.size(), 0);
#endif
  if (sent < 0) {
    sendErrors_.fetch_add(1);
    // Log only periodically to avoid log spam
    if (sendErrors_.load() % 100 == 1) {
      spdlog::warn("SyslogSink: send failed (total errors: {}): {}",
                   sendErrors_.load(), socketErrorString());
    }
  } else {
    messagesSent_.fetch_add(1);
  }
}

void SyslogSink::resolveHostname() {
  if (!config_.hostname.empty())
    return;

  std::array<char, 256> buf{};
#ifdef _WIN32
  if (::gethostname(buf.data(), static_cast<int>(buf.size())) == 0) {
#else
  if (::gethostname(buf.data(), buf.size()) == 0) {
#endif
    config_.hostname = buf.data();
  } else {
    config_.hostname = "nids-host";
  }
}

} // namespace nids::infra
