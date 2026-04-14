#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "netra/profiling/Metrics.hpp"

using namespace netra::profiling;

TEST(MetricsTest, TimerBasic) {
    Timer timer;
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    double elapsed = timer.stop();
    EXPECT_GT(elapsed, 0.0);
}

TEST(MetricsTest, PipelineMetricsBasic) {
    PipelineMetrics metrics;
    metrics.incrementCaptured();
    metrics.incrementParsed();
    metrics.incrementAnalyzed();
    
    EXPECT_EQ(metrics.getCapturedPackets(), 1);
    EXPECT_EQ(metrics.getParsedPackets(), 1);
    EXPECT_EQ(metrics.getAnalyzedPackets(), 1);
}
