#include "netra/profiling/Metrics.hpp"

#include <algorithm>
#include <cmath>

namespace netra::profiling {

// ============================================================================
// Timer Implementation
// ============================================================================

void Timer::start() {
    startTime_ = Clock::now();
}

double Timer::stop() {
    auto endTime = Clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime_);
    return static_cast<double>(duration.count());
}

double Timer::elapsed() const {
    auto currentTime = Clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        currentTime - startTime_);
    return static_cast<double>(duration.count());
}

void Timer::reset() {
    startTime_ = Clock::now();
}

// ============================================================================
// PipelineMetrics Implementation
// ============================================================================

void PipelineMetrics::incrementCaptured() {
    capturedPackets_.fetch_add(1, std::memory_order_relaxed);
}

void PipelineMetrics::incrementParsed() {
    parsedPackets_.fetch_add(1, std::memory_order_relaxed);
}

void PipelineMetrics::incrementAnalyzed() {
    analyzedPackets_.fetch_add(1, std::memory_order_relaxed);
}

void PipelineMetrics::addCaptureLatency(double ms) {
    atomicAdd(totalCaptureLatency_, ms);
    captureLatencyCount_.fetch_add(1, std::memory_order_relaxed);
}

void PipelineMetrics::addParseLatency(double ms) {
    atomicAdd(totalParseLatency_, ms);
    parseLatencyCount_.fetch_add(1, std::memory_order_relaxed);
}

void PipelineMetrics::addAnalyzeLatency(double ms) {
    atomicAdd(totalAnalyzeLatency_, ms);
    analyzeLatencyCount_.fetch_add(1, std::memory_order_relaxed);
}

uint64_t PipelineMetrics::getCapturedPackets() const {
    return capturedPackets_.load(std::memory_order_acquire);
}

uint64_t PipelineMetrics::getParsedPackets() const {
    return parsedPackets_.load(std::memory_order_acquire);
}

uint64_t PipelineMetrics::getAnalyzedPackets() const {
    return analyzedPackets_.load(std::memory_order_acquire);
}

double PipelineMetrics::getAvgCaptureLatency() const {
    auto count = captureLatencyCount_.load(std::memory_order_acquire);
    if (count == 0) {
        return 0.0;
    }
    auto total = totalCaptureLatency_.load(std::memory_order_acquire);
    return total / static_cast<double>(count);
}

double PipelineMetrics::getAvgParseLatency() const {
    auto count = parseLatencyCount_.load(std::memory_order_acquire);
    if (count == 0) {
        return 0.0;
    }
    auto total = totalParseLatency_.load(std::memory_order_acquire);
    return total / static_cast<double>(count);
}

double PipelineMetrics::getAvgAnalyzeLatency() const {
    auto count = analyzeLatencyCount_.load(std::memory_order_acquire);
    if (count == 0) {
        return 0.0;
    }
    auto total = totalAnalyzeLatency_.load(std::memory_order_acquire);
    return total / static_cast<double>(count);
}

std::string PipelineMetrics::formatMetrics() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "=== Pipeline Metrics ===\n";
    oss << "Captured Packets:     " << getCapturedPackets() << "\n";
    oss << "Parsed Packets:       " << getParsedPackets() << "\n";
    oss << "Analyzed Packets:     " << getAnalyzedPackets() << "\n";
    oss << "Avg Capture Latency:  " << getAvgCaptureLatency() << " ms\n";
    oss << "Avg Parse Latency:    " << getAvgParseLatency() << " ms\n";
    oss << "Avg Analyze Latency:  " << getAvgAnalyzeLatency() << " ms\n";

    return oss.str();
}

void PipelineMetrics::reset() {
    capturedPackets_.store(0, std::memory_order_release);
    parsedPackets_.store(0, std::memory_order_release);
    analyzedPackets_.store(0, std::memory_order_release);
    totalCaptureLatency_.store(0.0, std::memory_order_release);
    captureLatencyCount_.store(0, std::memory_order_release);
    totalParseLatency_.store(0.0, std::memory_order_release);
    parseLatencyCount_.store(0, std::memory_order_release);
    totalAnalyzeLatency_.store(0.0, std::memory_order_release);
    analyzeLatencyCount_.store(0, std::memory_order_release);
}

void PipelineMetrics::atomicAdd(std::atomic<double>& target, double value) {
    double expected = target.load(std::memory_order_relaxed);
    while (!target.compare_exchange_weak(expected, expected + value,
                                         std::memory_order_relaxed)) {
        // Retry
    }
}

} // namespace netra::profiling
