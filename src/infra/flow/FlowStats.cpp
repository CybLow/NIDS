#include "infra/flow/FlowStats.h"

#include <cassert>
#include <vector>

namespace nids::infra {

namespace {

/// Push max, min, mean, std from an accumulator, or 4 zeros if empty.
void pushLengthStats(std::vector<float>& features,
                     const WelfordAccumulator& acc) {
    if (acc.count() == 0) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(acc.max()));
        features.push_back(static_cast<float>(acc.min()));
        features.push_back(static_cast<float>(acc.mean()));
        features.push_back(static_cast<float>(acc.stddev()));
    }
}

/// Push total, mean, std, max, min from an accumulator, or 5 zeros if empty.
void pushIatStats(std::vector<float>& features,
                  const WelfordAccumulator& acc) {
    if (acc.count() == 0) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(acc.sum()));
        features.push_back(static_cast<float>(acc.mean()));
        features.push_back(static_cast<float>(acc.stddev()));
        features.push_back(static_cast<float>(acc.max()));
        features.push_back(static_cast<float>(acc.min()));
    }
}

/// Push a rate = count / durationSec if duration > 0, else push 0.
void pushRate(std::vector<float>& features, double count, double durationUs) {
    features.push_back(
        durationUs > 0 ? static_cast<float>(count / (durationUs / 1e6)) : 0.0f);
}

/// Push min, max, mean, std, variance from an accumulator, or 5 zeros.
void pushFullLengthStats(std::vector<float>& features,
                         const WelfordAccumulator& acc) {
    if (acc.count() == 0) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(acc.min()));
        features.push_back(static_cast<float>(acc.max()));
        features.push_back(static_cast<float>(acc.mean()));
        features.push_back(static_cast<float>(acc.stddev()));
        features.push_back(static_cast<float>(acc.populationVariance()));
    }
}

/// Push mean, std, max, min from an accumulator, or 4 zeros if empty.
void pushPeriodStats(std::vector<float>& features,
                     const WelfordAccumulator& acc) {
    if (acc.count() == 0) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(acc.mean()));
        features.push_back(static_cast<float>(acc.stddev()));
        features.push_back(static_cast<float>(acc.max()));
        features.push_back(static_cast<float>(acc.min()));
    }
}

/// Push avg bytes/bulk, avg packets/bulk, bulk rate, or 3 zeros.
void pushBulkStats(std::vector<float>& features,
                   const WelfordAccumulator& bytesAcc,
                   const WelfordAccumulator& pktsAcc,
                   double durationUs) {
    if (bytesAcc.count() == 0) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(bytesAcc.mean()));
        features.push_back(static_cast<float>(pktsAcc.mean()));
        features.push_back(
            durationUs > 0
                ? static_cast<float>(bytesAcc.sum() / (durationUs / 1e6))
                : 0.0f);
    }
}

/// Push a safe ratio = numerator / denominator, or 0 if denominator is 0.
void pushRatio(std::vector<float>& features, double numerator,
               double denominator) {
    features.push_back(
        denominator > 0 ? static_cast<float>(numerator / denominator) : 0.0f);
}

} // anonymous namespace

std::vector<float> FlowStats::toFeatureVector(std::uint16_t dstPort) const {
    std::vector<float> features;
    features.reserve(kFlowFeatureCount);

    auto durationUs = static_cast<double>(lastTimeUs - startTimeUs);
    if (durationUs < 0)
        durationUs = 0;

    // 0: Destination Port
    features.push_back(static_cast<float>(dstPort));
    // 1: Flow Duration (microseconds)
    features.push_back(static_cast<float>(durationUs));
    // 2-5: Total Fwd/Bwd Packets and Bytes
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 6-9: Fwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, fwdLengthAcc);
    // 10-13: Bwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, bwdLengthAcc);
    // 14-15: Flow Bytes/s, Flow Packets/s
    pushRate(features, static_cast<double>(totalFwdBytes + totalBwdBytes),
             durationUs);
    pushRate(features, static_cast<double>(totalFwdPackets + totalBwdPackets),
             durationUs);
    // 16-19: Flow IAT Mean, Std, Max, Min
    pushPeriodStats(features, flowIatAcc);
    // 20-24: Fwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, fwdIatAcc);
    // 25-29: Bwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, bwdIatAcc);
    // 30-33: Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags
    features.push_back(static_cast<float>(fwdPshFlags));
    features.push_back(static_cast<float>(bwdPshFlags));
    features.push_back(static_cast<float>(fwdUrgFlags));
    features.push_back(static_cast<float>(bwdUrgFlags));
    // 34-35: Fwd Header Length, Bwd Header Length
    features.push_back(static_cast<float>(fwdHeaderBytes));
    features.push_back(static_cast<float>(bwdHeaderBytes));
    // 36-37: Fwd Packets/s, Bwd Packets/s
    pushRate(features, static_cast<double>(totalFwdPackets), durationUs);
    pushRate(features, static_cast<double>(totalBwdPackets), durationUs);
    // 38-42: Packet Length Min, Max, Mean, Std, Variance (all packets)
    pushFullLengthStats(features, allLengthAcc);
    // 43-50: FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts
    features.push_back(static_cast<float>(finCount));
    features.push_back(static_cast<float>(synCount));
    features.push_back(static_cast<float>(rstCount));
    features.push_back(static_cast<float>(pshCount));
    features.push_back(static_cast<float>(ackCount));
    features.push_back(static_cast<float>(urgCount));
    features.push_back(static_cast<float>(cwrCount));
    features.push_back(static_cast<float>(eceCount));
    // 51: Down/Up Ratio (backward/forward packets)
    pushRatio(features, static_cast<double>(totalBwdPackets),
              static_cast<double>(totalFwdPackets));
    // 52: Average Packet Size
    std::uint64_t totalPackets = totalFwdPackets + totalBwdPackets;
    std::uint64_t totalBytes = totalFwdBytes + totalBwdBytes;
    pushRatio(features, static_cast<double>(totalBytes),
              static_cast<double>(totalPackets));
    // 53-54: Fwd Segment Size Avg, Bwd Segment Size Avg
    pushRatio(features, static_cast<double>(totalFwdBytes - fwdHeaderBytes),
              static_cast<double>(totalFwdPackets));
    pushRatio(features, static_cast<double>(totalBwdBytes - bwdHeaderBytes),
              static_cast<double>(totalBwdPackets));
    // 55-57: Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg
    pushBulkStats(features, fwdBulkBytesAcc, fwdBulkPktsAcc, durationUs);
    // 58-60: Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
    pushBulkStats(features, bwdBulkBytesAcc, bwdBulkPktsAcc, durationUs);
    // 61-64: Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets,
    // Subflow Bwd Bytes
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 65-66: Init_Win_bytes_forward, Init_Win_bytes_backward
    features.push_back(static_cast<float>(fwdInitWinBytes));
    features.push_back(static_cast<float>(bwdInitWinBytes));
    // 67-68: act_data_pkt_fwd, min_seg_size_forward
    features.push_back(static_cast<float>(actDataPktFwd));
    features.push_back(static_cast<float>(minSegSizeForward));
    // 69-72: Active Mean, Std, Max, Min
    pushPeriodStats(features, activeAcc);
    // 73-76: Idle Mean, Std, Max, Min
    pushPeriodStats(features, idleAcc);

    assert(features.size() == static_cast<std::size_t>(kFlowFeatureCount) &&
           "toFeatureVector() output size must match kFlowFeatureCount");
    return features;
}

const std::vector<std::string>& flowFeatureNames() {
    // Feature names matching toFeatureVector() order.
    // 77 features total (kFlowFeatureCount).
    static const std::vector<std::string> names = {
        "Destination Port",        "Flow Duration",
        "Total Fwd Packets",       "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max",   "Fwd Packet Length Min",
        "Fwd Packet Length Mean",  "Fwd Packet Length Std",
        "Bwd Packet Length Max",   "Bwd Packet Length Min",
        "Bwd Packet Length Mean",  "Bwd Packet Length Std",
        "Flow Bytes/s",            "Flow Packets/s",
        "Flow IAT Mean",           "Flow IAT Std",
        "Flow IAT Max",            "Flow IAT Min",
        "Fwd IAT Total",           "Fwd IAT Mean",
        "Fwd IAT Std",             "Fwd IAT Max",
        "Fwd IAT Min",             "Bwd IAT Total",
        "Bwd IAT Mean",            "Bwd IAT Std",
        "Bwd IAT Max",             "Bwd IAT Min",
        "Fwd PSH Flags",           "Bwd PSH Flags",
        "Fwd URG Flags",           "Bwd URG Flags",
        "Fwd Header Length",       "Bwd Header Length",
        "Fwd Packets/s",           "Bwd Packets/s",
        "Min Packet Length",        "Max Packet Length",
        "Packet Length Mean",       "Packet Length Std",
        "Packet Length Variance",   "FIN Flag Count",
        "SYN Flag Count",          "RST Flag Count",
        "PSH Flag Count",          "ACK Flag Count",
        "URG Flag Count",          "CWE Flag Count",
        "ECE Flag Count",          "Down/Up Ratio",
        "Average Packet Size",     "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",    "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",    "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",      "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",       "Subflow Fwd Packets",
        "Subflow Fwd Bytes",       "Subflow Bwd Packets",
        "Subflow Bwd Bytes",       "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd",
        "min_seg_size_forward",    "Active Mean",
        "Active Std",              "Active Max",
        "Active Min",              "Idle Mean",
        "Idle Std",                "Idle Max",
        "Idle Min",
    };
    assert(names.size() == static_cast<std::size_t>(kFlowFeatureCount) &&
           "flowFeatureNames() size must match kFlowFeatureCount");
    return names;
}

core::FlowInfo buildFlowInfo(const FlowKey& key, const FlowStats& stats) {
    core::FlowInfo info;
    info.srcIp = key.srcIp;
    info.dstIp = key.dstIp;
    info.srcPort = key.srcPort;
    info.dstPort = key.dstPort;
    info.protocol = key.protocol;

    info.totalFwdPackets = stats.totalFwdPackets;
    info.totalBwdPackets = stats.totalBwdPackets;

    auto durationUs = static_cast<double>(stats.lastTimeUs - stats.startTimeUs);
    info.flowDurationUs = durationUs;

    if (durationUs > 0.0) {
        double durationSec = durationUs / 1'000'000.0;
        info.fwdPacketsPerSecond =
            static_cast<double>(stats.totalFwdPackets) / durationSec;
        info.bwdPacketsPerSecond =
            static_cast<double>(stats.totalBwdPackets) / durationSec;
    }

    info.synFlagCount = stats.synCount;
    info.ackFlagCount = stats.ackCount;
    info.rstFlagCount = stats.rstCount;
    info.finFlagCount = stats.finCount;

    auto totalPackets = stats.totalFwdPackets + stats.totalBwdPackets;
    auto totalBytes = stats.totalFwdBytes + stats.totalBwdBytes;
    if (totalPackets > 0) {
        info.avgPacketSize =
            static_cast<double>(totalBytes) / static_cast<double>(totalPackets);
    }

    return info;
}

} // namespace nids::infra
