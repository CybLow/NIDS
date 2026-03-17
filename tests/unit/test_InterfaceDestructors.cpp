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
