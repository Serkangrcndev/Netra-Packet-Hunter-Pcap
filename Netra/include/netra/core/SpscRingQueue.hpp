#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <utility>
#include <vector>

namespace netra {

template <typename T>
class SpscRingQueue {
public:
    explicit SpscRingQueue(std::size_t capacity)
        : capacity_(std::max<std::size_t>(capacity + 1U, 2U)),
          buffer_(capacity_) {}

    bool tryPush(const T& value) {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = increment(head);
        if (next == tail_.load(std::memory_order_acquire)) {
            return false;
        }

        buffer_[head] = value;
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool tryPush(T&& value) {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = increment(head);
        if (next == tail_.load(std::memory_order_acquire)) {
            return false;
        }

        buffer_[head] = std::move(value);
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool tryPop(T& value) {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) {
            return false;
        }

        value = std::move(buffer_[tail]);
        tail_.store(increment(tail), std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::size_t size() const {
        const auto head = head_.load(std::memory_order_acquire);
        const auto tail = tail_.load(std::memory_order_acquire);
        return head >= tail ? head - tail : capacity_ - tail + head;
    }

    [[nodiscard]] std::size_t capacity() const {
        return capacity_ - 1U;
    }

private:
    [[nodiscard]] std::size_t increment(std::size_t index) const {
        ++index;
        if (index == capacity_) {
            index = 0;
        }
        return index;
    }

    const std::size_t capacity_;
    std::vector<T> buffer_;
    std::atomic<std::size_t> head_ {0};
    std::atomic<std::size_t> tail_ {0};
};

}  // namespace netra

