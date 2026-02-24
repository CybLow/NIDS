#include "infra/flow/NativeFlowExtractor.h"

#include <pcap.h>
#include <fstream>
#include <sstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iostream>

namespace nids::infra {

bool FlowKey::operator<(const FlowKey& other) const {
    if (srcIp != other.srcIp) return srcIp < other.srcIp;
    if (dstIp != other.dstIp) return dstIp < other.dstIp;
    if (srcPort != other.srcPort) return srcPort < other.srcPort;
    if (dstPort != other.dstPort) return dstPort < other.dstPort;
    return protocol < other.protocol;
}

namespace {

template<typename Container>
double mean(const Container& c) {
    if (c.empty()) return 0.0;
    double sum = std::accumulate(c.begin(), c.end(), 0.0);
    return sum / static_cast<double>(c.size());
}

template<typename Container>
double stddev(const Container& c) {
    if (c.size() <= 1) return 0.0;
    double m = mean(c);
    double accum = 0.0;
    for (const auto& val : c) {
        accum += (static_cast<double>(val) - m) * (static_cast<double>(val) - m);
    }
    return std::sqrt(accum / static_cast<double>(c.size() - 1));
}

} // anonymous namespace

std::vector<float> FlowStats::toFeatureVector() const {
    std::vector<float> features;
    features.reserve(79);

    double durationUs = static_cast<double>(lastTimeUs - startTimeUs);
    features.push_back(static_cast<float>(durationUs));

    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdBytes));

    auto pushStats = [&features](const auto& lengths) {
        if (lengths.empty()) {
            features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
        } else {
            features.push_back(static_cast<float>(*std::max_element(lengths.begin(), lengths.end())));
            features.push_back(static_cast<float>(*std::min_element(lengths.begin(), lengths.end())));
            features.push_back(static_cast<float>(mean(lengths)));
            features.push_back(static_cast<float>(stddev(lengths)));
        }
    };

    pushStats(fwdPacketLengths);
    pushStats(bwdPacketLengths);

    if (durationUs > 0) {
        double totalPackets = static_cast<double>(totalFwdPackets + totalBwdPackets);
        features.push_back(static_cast<float>(totalPackets / (durationUs / 1e6)));
        double totalBytes = static_cast<double>(totalFwdBytes + totalBwdBytes);
        features.push_back(static_cast<float>(totalBytes / (durationUs / 1e6)));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }

    pushStats(fwdIatUs);
    pushStats(bwdIatUs);

    features.push_back(static_cast<float>(fwdPshFlags));
    features.push_back(static_cast<float>(bwdPshFlags));
    features.push_back(static_cast<float>(fwdUrgFlags));
    features.push_back(static_cast<float>(bwdUrgFlags));

    features.push_back(static_cast<float>(finCount));
    features.push_back(static_cast<float>(synCount));
    features.push_back(static_cast<float>(rstCount));
    features.push_back(static_cast<float>(ackCount));

    // Pad to 79 features
    while (features.size() < 79) {
        features.push_back(0.0f);
    }

    return features;
}

bool NativeFlowExtractor::extractFlows(const std::string& pcapPath,
                                         const std::string& outputCsvPath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto* handle = pcap_open_offline(pcapPath.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Cannot open pcap file: " << errbuf << std::endl;
        return false;
    }

    flows_.clear();
    struct pcap_pkthdr* header;
    const unsigned char* data;

    while (pcap_next_ex(handle, &header, &data) > 0) {
        std::int64_t tsUs = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000
                            + header->ts.tv_usec;
        processPacket(data, header->caplen, tsUs);
    }

    pcap_close(handle);
    writeCsv(outputCsvPath);
    return true;
}

void NativeFlowExtractor::processPacket(const std::uint8_t* /*data*/,
                                          std::uint32_t /*len*/,
                                          std::int64_t /*timestampUs*/) {
    // TODO: Parse Ethernet/IP/TCP/UDP headers, extract FlowKey,
    // update FlowStats for the corresponding flow.
    // This is where the CICFlowMeter algorithm would be reimplemented.
}

void NativeFlowExtractor::writeCsv(const std::string& outputPath) const {
    std::ofstream file(outputPath);
    if (!file.is_open()) return;

    file << "feature_0";
    for (int i = 1; i < 79; ++i) {
        file << ",feature_" << i;
    }
    file << "\n";

    for (const auto& [key, stats] : flows_) {
        auto features = stats.toFeatureVector();
        for (std::size_t i = 0; i < features.size(); ++i) {
            if (i > 0) file << ",";
            file << features[i];
        }
        file << "\n";
    }
}

std::vector<std::vector<float>> NativeFlowExtractor::loadFeatures(
    const std::string& csvPath) {
    std::vector<std::vector<float>> result;
    std::ifstream file(csvPath);
    if (!file.is_open()) return result;

    std::string line;
    std::getline(file, line); // skip header

    while (std::getline(file, line)) {
        std::vector<float> row;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, ',')) {
            try {
                row.push_back(std::stof(cell));
            } catch (...) {
                row.push_back(0.0f);
            }
        }
        while (row.size() < 79) row.push_back(0.0f);
        result.push_back(std::move(row));
    }

    return result;
}

} // namespace nids::infra
