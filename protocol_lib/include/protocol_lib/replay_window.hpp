#pragma once

#include <cstdint>
#include <deque>
#include <unordered_set>

namespace protocol::replay {

//! Sliding window for detecting replay attacks based on sequence numbers.
class ReplayWindow {
  public:
    //! Constructs a replay window with specified capacity.
    //! @param window [in] Maximum number of sequence numbers to remember.
    explicit ReplayWindow(size_t window = 256);

    //! Checks if a sequence number has been seen before.
    //! @param seq [in] Sequence number to check.
    //! @return True if seq was previously accepted.
    bool contains(uint64_t seq) const;

    //! Records a sequence number as seen (without checking).
    //! @param seq [in] Sequence number to remember.
    void remember(uint64_t seq);

    //! Checks and accepts a sequence number atomically.
    //! @param seq [in] Sequence number to validate and record.
    //! @return True if seq is new and was accepted, false if replay detected.
    bool accept(uint64_t seq);

  private:
    //! Maximum number of sequence numbers to track.
    size_t _window;

    //! Hash set for O(1) lookup of seen sequence numbers.
    std::unordered_set<uint64_t> _seen;
    //! Queue maintaining insertion order for FIFO eviction.
    std::deque<uint64_t> _order;

    //! Checks if seq exists in the seen set.
    //! @param seq [in] Sequence number to look up.
    //! @return True if already seen.
    bool isAlreadySeen(uint64_t seq) const;

    //! Removes the oldest entry if window capacity is exceeded.
    void evictOldestIfFull();
};

}  // namespace protocol::replay
