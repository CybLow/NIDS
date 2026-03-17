#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"
#include "helpers/MockOutputSink.h"
#include "helpers/MockPacketCapture.h"

#include "app/HeadlessCaptureRunner.h"

#include <atomic>
#include <string>

using namespace nids::app;
using namespace nids::testing;
using ::testing::_;

// ── Immediate shutdown ──────────────────────────────────────────────

TEST(HeadlessCaptureRunner, runHeadlessCapture_immediateShutdown_returnsZero) {
  MockPacketCapture capture;
  MockFlowExtractorFull extractor;
  MockAnalyzerWithConfidence analyzer;
  MockNormalizer normalizer;

  // Extractor: capture the flow-completion callback (no-op here).
  extractor.captureCallback();
  ON_CALL(extractor, setFlowCompletionCallback(_))
      .WillByDefault(::testing::Return());
  ON_CALL(extractor, reset()).WillByDefault(::testing::Return());
  ON_CALL(extractor, finalizeAllFlows()).WillByDefault(::testing::Return());

  // Capture: record the raw-packet callback, start/stop are no-ops.
  ON_CALL(capture, setRawPacketCallback(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, startCapture(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, stopCapture()).WillByDefault(::testing::Return());

  HeadlessRunnerConfig config;
  config.interfaceName = "lo";
  config.capture = &capture;
  config.flowExtractor = &extractor;
  config.analyzer = &analyzer;
  config.normalizer = &normalizer;
  config.hybridService = nullptr;

  // Signal immediate shutdown.
  config.shutdownRequested = [] { return true; };

  const int rc = runHeadlessCapture(config);
  EXPECT_EQ(rc, 0);
}

// ── Shutdown after a few poll iterations ─────────────────────────────

TEST(HeadlessCaptureRunner, runHeadlessCapture_delayedShutdown_returnsZero) {
  MockPacketCapture capture;
  MockFlowExtractorFull extractor;
  MockAnalyzerWithConfidence analyzer;
  MockNormalizer normalizer;

  extractor.captureCallback();
  ON_CALL(extractor, setFlowCompletionCallback(_))
      .WillByDefault(::testing::Return());
  ON_CALL(extractor, reset()).WillByDefault(::testing::Return());
  ON_CALL(extractor, finalizeAllFlows()).WillByDefault(::testing::Return());

  ON_CALL(capture, setRawPacketCallback(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, startCapture(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, stopCapture()).WillByDefault(::testing::Return());

  std::atomic<int> polls{0};

  HeadlessRunnerConfig config;
  config.interfaceName = "eth0";
  config.capture = &capture;
  config.flowExtractor = &extractor;
  config.analyzer = &analyzer;
  config.normalizer = &normalizer;
  config.hybridService = nullptr;

  // Shutdown after 2 poll iterations.
  config.shutdownRequested = [&polls] { return ++polls >= 2; };

  const int rc = runHeadlessCapture(config);
  EXPECT_EQ(rc, 0);
  EXPECT_GE(polls.load(), 2);
}

// ── Output sinks are wired ──────────────────────────────────────────

TEST(HeadlessCaptureRunner,
     runHeadlessCapture_withSink_sinkStartAndStopCalled) {
  MockPacketCapture capture;
  MockFlowExtractorFull extractor;
  MockAnalyzerWithConfidence analyzer;
  MockNormalizer normalizer;
  MockOutputSink sink;

  extractor.captureCallback();
  ON_CALL(extractor, setFlowCompletionCallback(_))
      .WillByDefault(::testing::Return());
  ON_CALL(extractor, reset()).WillByDefault(::testing::Return());
  ON_CALL(extractor, finalizeAllFlows()).WillByDefault(::testing::Return());

  ON_CALL(capture, setRawPacketCallback(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, startCapture(_)).WillByDefault(::testing::Return());
  ON_CALL(capture, stopCapture()).WillByDefault(::testing::Return());

  ON_CALL(sink, name()).WillByDefault(::testing::Return("test-sink"));
  EXPECT_CALL(sink, start()).WillOnce(::testing::Return(true));
  EXPECT_CALL(sink, stop()).Times(1);

  HeadlessRunnerConfig config;
  config.interfaceName = "lo";
  config.capture = &capture;
  config.flowExtractor = &extractor;
  config.analyzer = &analyzer;
  config.normalizer = &normalizer;
  config.hybridService = nullptr;
  config.sinks = {&sink};
  config.shutdownRequested = [] { return true; };

  const int rc = runHeadlessCapture(config);
  EXPECT_EQ(rc, 0);
}
