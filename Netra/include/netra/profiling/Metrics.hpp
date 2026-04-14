#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace netra::profiling {

/**
 * @brief High-resolution timer for performance measurements
 */
class Timer {
public:
    /**
     * @brief Start the timer
     */
    void start();

    /**
     * @brief Stop the timer
     * @return Elapsed time in milliseconds
     */
    [[nodiscard]] double stop();

    /**
     * @brief Get elapsed time without stopping
     * @return Elapsed time in milliseconds
     */
    [[nodiscard]] double elapsed() const;

    /**
     * @brief Reset the timer
     */
    void reset();

private:
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point startTime_;
};

/**
 * @brief Pipeline performance metrics tracker
 *
 * Thread-safe atomic counters for tracking packet processing
 * through the capture -> parse -> analyze pipeline.
 */
class PipelineMetrics {
public:
    /**
     * @brief Increment captured packets counter
     */
    void incrementCaptured();

    /**
     * @brief Increment parsed packets counter
     */
    void incrementParsed();

    /**
     * @brief Increment analyzed packets counter
     */
    void incrementAnalyzed();

    /**
     * @brief Add capture latency measurement (in milliseconds)
     */
    void addCaptureLatency(double ms);

    /**
     * @brief Add parse latency measurement (in milliseconds)
     */
    void addParseLatency(double ms);

    /**
     * @brief Add analyze latency measurement (in milliseconds)
     */
    void addAnalyzeLatency(double ms);

    /**
     * @brief Get captured packets count
     */
    [[nodiscard]] uint64_t getCapturedPackets() const;

    /**
     * @brief Get parsed packets count
     */
    [[nodiscard]] uint64_t getParsedPackets() const;

    /**
     * @brief Get analyzed packets count
     */
    [[nodiscard]] uint64_t getAnalyzedPackets() const;

    /**
     * @brief Get average capture latency in milliseconds
     */
    [[nodiscard]] double getAvgCaptureLatency() const;

    /**
     * @brief Get average parse latency in milliseconds
     */
    [[nodiscard]] double getAvgParseLatency() const;

    /**
     * @brief Get average analyze latency in milliseconds
     */
    [[nodiscard]] double getAvgAnalyzeLatency() const;

    /**
     * @brief Get formatted metrics string
     */
    [[nodiscard]] std::string formatMetrics() const;

    /**
     * @brief Reset all metrics
     */
    void reset();

private:
    std::atomic<uint64_t> capturedPackets_{0};
    std::atomic<uint64_t> parsedPackets_{0};
    std::atomic<uint64_t> analyzedPackets_{0};

    std::atomic<double> totalCaptureLatency_{0.0};
    std::atomic<uint64_t> captureLatencyCount_{0};

    std::atomic<double> totalParseLatency_{0.0};
    std::atomic<uint64_t> parseLatencyCount_{0};

    std::atomic<double> totalAnalyzeLatency_{0.0};
    std::atomic<uint64_t> analyzeLatencyCount_{0};

    // Helper for atomic addition
    static void atomicAdd(std::atomic<double>& target, double value);
};

} // namespace netra::profiling
