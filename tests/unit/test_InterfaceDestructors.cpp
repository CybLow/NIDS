#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"
#include "helpers/MockOutputSink.h"
#include "helpers/MockPacketCapture.h"
#include "helpers/MockRuleEngine.h"

#include "core/services/IAnalysisRepository.h"
#include "core/services/ICommand.h"
#include "core/services/IFlowIndex.h"
#include "core/services/IHuntEngine.h"
#include "core/services/IPcapStore.h"

#include <memory>

using namespace nids::core;
using namespace nids::testing;

/// Minimal mock for IAnalysisRepository to exercise virtual destructor.
namespace {

class MockAnalysisRepository : public IAnalysisRepository {
public:
  void store(std::size_t /*flowIndex*/,
             const DetectionResult & /*result*/) override {}
  [[nodiscard]] DetectionResult get(std::size_t /*flowIndex*/) const override {
    return {};
  }
  [[nodiscard]] std::size_t size() const noexcept override { return 0; }
  void clear() override {}
};

/// Minimal mock for ICommand to exercise virtual destructor.
class MockCommand : public ICommand {
public:
  void execute() override {}
  void undo() override {}
  [[nodiscard]] std::string_view name() const noexcept override {
    return "MockCmd";
  }
};

} // anonymous namespace

// ── Virtual destructor coverage ─────────────────────────────────────
// Each test instantiates a derived mock via unique_ptr<Base> and destroys it,
// exercising the virtual destructor in the base interface.

TEST(InterfaceDestructors, IAnalysisRepository_destructor) {
  std::unique_ptr<IAnalysisRepository> p =
      std::make_unique<MockAnalysisRepository>();
  p.reset(); // Explicit destroy through base pointer.
}

TEST(InterfaceDestructors, ICommand_destructor) {
  std::unique_ptr<ICommand> p = std::make_unique<MockCommand>();
  p.reset();
}

TEST(InterfaceDestructors, IOutputSink_destructor) {
  std::unique_ptr<IOutputSink> p = std::make_unique<MockOutputSink>();
  p.reset();
}

TEST(InterfaceDestructors, IFlowExtractor_destructor) {
  std::unique_ptr<IFlowExtractor> p = std::make_unique<MockFlowExtractor>();
  p.reset();
}

TEST(InterfaceDestructors, IPacketCapture_destructor) {
  std::unique_ptr<IPacketCapture> p = std::make_unique<MockPacketCapture>();
  p.reset();
}

TEST(InterfaceDestructors, IRuleEngine_destructor) {
  std::unique_ptr<IRuleEngine> p = std::make_unique<MockRuleEngine>();
  p.reset();
}

TEST(InterfaceDestructors, IFeatureNormalizer_destructor) {
  std::unique_ptr<IFeatureNormalizer> p = std::make_unique<MockNormalizer>();
  p.reset();
}

TEST(InterfaceDestructors, IPacketAnalyzer_destructor) {
  std::unique_ptr<IPacketAnalyzer> p = std::make_unique<MockAnalyzer>();
  p.reset();
}

// ── Phase 13: Threat Hunting interfaces ─────────────────────────────

namespace {

class MockPcapStore : public IPcapStore {
public:
    void store(std::span<const std::uint8_t>, int64_t) override {}
    [[nodiscard]] std::size_t sizeBytes() const noexcept override { return 0; }
    void evict(std::size_t) override {}
    [[nodiscard]] std::vector<PcapFileInfo> listFiles() const override {
        return {};
    }
    void flush() override {}
};

class MockFlowIndex : public IFlowIndex {
public:
    void index(const FlowInfo&, const DetectionResult&,
               std::string_view, std::size_t) override {}
    [[nodiscard]] std::vector<IndexedFlow> query(
        const FlowQuery&) override { return {}; }
    [[nodiscard]] std::size_t count(
        const FlowQuery&) const override { return 0; }
    [[nodiscard]] std::vector<std::string> distinctValues(
        std::string_view, std::size_t) const override { return {}; }
    [[nodiscard]] FlowStatsSummary aggregate(
        const FlowQuery&) const override { return {}; }
    void optimize() override {}
    [[nodiscard]] std::size_t sizeBytes() const noexcept override { return 0; }
};

class MockHuntEngine : public IHuntEngine {
public:
    [[nodiscard]] HuntResult retroactiveAnalysis(
        const std::filesystem::path&) override { return {}; }
    [[nodiscard]] HuntResult iocSearch(
        const IocSearchQuery&) override { return {}; }
    [[nodiscard]] HuntResult correlateByIp(
        std::string_view, int64_t, int64_t) override { return {}; }
    [[nodiscard]] Timeline buildTimeline(
        const std::vector<IndexedFlow>&) override { return {}; }
    [[nodiscard]] std::vector<AnomalyResult> detectAnomalies(
        int64_t, int64_t) override { return {}; }
    void setProgressCallback(ProgressCallback) override {}
};

} // anonymous namespace

TEST(InterfaceDestructors, IPcapStore_destructor) {
    std::unique_ptr<IPcapStore> p = std::make_unique<MockPcapStore>();
    p.reset();
}

TEST(InterfaceDestructors, IFlowIndex_destructor) {
    std::unique_ptr<IFlowIndex> p = std::make_unique<MockFlowIndex>();
    p.reset();
}

TEST(InterfaceDestructors, IHuntEngine_destructor) {
    std::unique_ptr<IHuntEngine> p = std::make_unique<MockHuntEngine>();
    p.reset();
}
