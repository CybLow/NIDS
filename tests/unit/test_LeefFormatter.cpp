#include "infra/output/LeefFormatter.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"

#include "helpers/TestFixtures.h"
#include <gtest/gtest.h>

#include <string>

using namespace nids;

namespace {
using nids::testing::makeFlow;
using nids::testing::makeResult;

} // namespace

TEST(LeefFormatter, format_startsWithLeefHeader) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_TRUE(out.starts_with("LEEF:2.0|NIDS|NIDS|0.2.0|"));
}

TEST(LeefFormatter, format_containsFlowTuple) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto out = fmt.format(1, result, flow);

    EXPECT_NE(out.find("src=10.0.0.1"), std::string::npos);
    EXPECT_NE(out.find("dst=192.168.1.100"), std::string::npos);
    EXPECT_NE(out.find("srcPort=54321"), std::string::npos);
    EXPECT_NE(out.find("dstPort=80"), std::string::npos);
}

TEST(LeefFormatter, format_containsProtocolName) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("proto=TCP"), std::string::npos);
}

TEST(LeefFormatter, format_udpProtocol) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::DdosUdp, 0.8f, 0.6f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("proto=UDP"), std::string::npos);
}

TEST(LeefFormatter, format_containsCategory) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::SshBruteForce, 0.85f, 0.78f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("cat=SSH Brute Force"), std::string::npos);
}

TEST(LeefFormatter, format_containsReason) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::SynFlood, 0.9f, 0.85f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("reason="), std::string::npos);
    EXPECT_NE(out.find("SYN Flood detected"), std::string::npos);
}

TEST(LeefFormatter, severity_zeroCombinedScore_returnsOne) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    // LEEF min severity is 1
    EXPECT_NE(out.find("sev=1"), std::string::npos);
}

TEST(LeefFormatter, severity_maxCombinedScore_returnsTen) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::DdosUdp, 0.99f, 1.0f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 17);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("sev=10"), std::string::npos);
}

TEST(LeefFormatter, format_containsEventId) {
    infra::LeefFormatter fmt;
    auto result = makeResult(core::AttackType::PortScanning, 0.7f, 0.55f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    // EventID should be NIDS-<attackTypeIndex>
    EXPECT_NE(out.find("NIDS-12"), std::string::npos);  // PortScanning = 12
}
