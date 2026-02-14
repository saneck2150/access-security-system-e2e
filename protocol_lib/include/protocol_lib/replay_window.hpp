#pragma once

#include <cstdint>
#include <deque>
#include <unordered_set>

namespace protocol::replay {

class ReplayWindow {
  public:
    explicit ReplayWindow(size_t window = 256);

    bool contains(uint64_t seq) const;
    void remember(uint64_t seq);
    bool accept(uint64_t seq);

  private:
    // config
    size_t _window;

    // state
    std::unordered_set<uint64_t> _seen;
    std::deque<uint64_t> _order;

    // helper functions
    bool isAlreadySeen(uint64_t seq) const;
    void evictOldestIfFull();
};

} // namespace protocol::replay