#include "infra/flow/TcpReassembler.h"

#include <pcapplusplus/TcpReassembly.h>

#include <spdlog/spdlog.h>

#include <utility>

namespace nids::infra {

TcpReassembler::TcpReassembler(ReassemblyConfig config)
    : config_(std::move(config)) {
    reassembly_ = std::make_unique<pcpp::TcpReassembly>(
        onMessageReady, this, onConnectionStart, onConnectionEnd);
}

TcpReassembler::~TcpReassembler() {
    try {
        flushAll();
    } catch (...) {
        // Destructors must not throw.
    }
}

void TcpReassembler::setCallback(StreamCallback cb) {
    callback_ = std::move(cb);
}

void TcpReassembler::processPacket(pcpp::RawPacket& packet) {
    reassembly_->reassemblePacket(&packet);
}

void TcpReassembler::flushAll() {
    reassembly_->closeAllConnections();
}

void TcpReassembler::reset() {
    std::scoped_lock lock{mutex_};
    streams_.clear();
    completedStreams_ = 0;
    reassembly_ = std::make_unique<pcpp::TcpReassembly>(
        onMessageReady, this, onConnectionStart, onConnectionEnd);
}

std::size_t TcpReassembler::activeStreams() const noexcept {
    std::scoped_lock lock{mutex_};
    return streams_.size();
}

std::size_t TcpReassembler::completedStreams() const noexcept {
    return completedStreams_;
}

// ── PcapPlusPlus callbacks ──────────────────────────────────────────

void TcpReassembler::onConnectionStart(
    const pcpp::ConnectionData& connectionData, void* userData) {
    auto* self = static_cast<TcpReassembler*>(userData);
    std::scoped_lock lock{self->mutex_};

    if (self->streams_.size() >= self->config_.maxConcurrentStreams) {
        return; // Drop new connections when at capacity.
    }

    StreamState state;
    state.flow.srcIp = connectionData.srcIP.toString();
    state.flow.dstIp = connectionData.dstIP.toString();
    state.flow.srcPort = connectionData.srcPort;
    state.flow.dstPort = connectionData.dstPort;
    state.flow.protocol = 6; // TCP

    self->streams_[connectionData.flowKey] = std::move(state);
}

void TcpReassembler::onMessageReady(
    std::int8_t side,
    const pcpp::TcpStreamData& streamData,
    void* userData) {
    auto* self = static_cast<TcpReassembler*>(userData);
    std::scoped_lock lock{self->mutex_};

    auto connId = streamData.getConnectionData().flowKey;
    auto it = self->streams_.find(connId);
    if (it == self->streams_.end()) return;

    auto& stream = it->second;
    const auto* data = streamData.getData();
    const auto len = streamData.getDataLength();

    // Check size limit.
    if (stream.totalBytes + len > self->config_.maxStreamSize) {
        // Flush early — scan what we have so far.
        self->deliverStream(connId);
        return;
    }

    if (side == 0) { // Client to server
        stream.clientData.insert(
            stream.clientData.end(), data, data + len);
    } else { // Server to client
        stream.serverData.insert(
            stream.serverData.end(), data, data + len);
    }
    stream.totalBytes += len;
}

void TcpReassembler::onConnectionEnd(
    const pcpp::ConnectionData& connectionData,
    [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason,
    void* userData) {
    auto* self = static_cast<TcpReassembler*>(userData);
    std::scoped_lock lock{self->mutex_};
    self->deliverStream(connectionData.flowKey);
}

void TcpReassembler::deliverStream(std::uint32_t connId) {
    auto it = streams_.find(connId);
    if (it == streams_.end()) return;

    auto& stream = it->second;
    if (callback_ && stream.totalBytes > 0) {
        callback_(stream.flow, stream.clientData, stream.serverData);
    }

    ++completedStreams_;
    streams_.erase(it);
}

} // namespace nids::infra
