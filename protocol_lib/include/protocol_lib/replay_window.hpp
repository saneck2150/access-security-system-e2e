#pragma once

#include <cstdint>
#include <deque>
#include <unordered_set>

//! Sliding window replay protection for sequence number validation.
namespace protocol::replay {

//! Sliding window for detecting replay attacks based on sequence numbers.
class ReplayWindow {
  public:
    //! Constructs a replay window with specified capacity.
    //! @param [in] window Maximum number of sequence numbers to remember.
    explicit ReplayWindow(size_t window = 256);

    //! Checks if a sequence number has been seen before.
    //! @param [in] seq Sequence number to check.
    //! @return True if seq was previously accepted.
    bool contains(uint64_t seq) const;

    //! Records a sequence number as seen (without checking).
    //! @param [in] seq Sequence number to remember.
    void remember(uint64_t seq);

    //! Checks and accepts a sequence number atomically.
    //! @param [in] seq Sequence number to validate and record.
    //! @return True if seq is new and was accepted, false if replay detected.
    bool accept(uint64_t seq);

  private:
    //! Maximum number of sequence numbers to track.
    size_t _window;

    //! Highest sequence number seen so far.
    uint64_t _maxSeen = 0;

    //! Hash set for O(1) lookup of seen sequence numbers.
    std::unordered_set<uint64_t> _seen;
    //! Queue maintaining insertion order for FIFO eviction.
    std::deque<uint64_t> _order;

    //! Checks if seq is too old (older than maxSeen - window).
    //! @param [in] seq Sequence number to check.
    //! @return True if seq is outside the valid window.
    bool isTooOld(uint64_t seq) const;

    //! Checks if seq exists in the seen set.
    //! @param [in] seq Sequence number to look up.
    //! @return True if already seen.
    bool isAlreadySeen(uint64_t seq) const;

    //! Removes the oldest entry if window capacity is exceeded.
    void evictOldestIfFull();
};

}  // namespace protocol::replay
