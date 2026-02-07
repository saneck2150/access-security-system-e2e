#pragma once
#include <cstdint>
#include <deque>
#include <unordered_set>

namespace protocol::replay {

class ReplayWindow {
  public:
    explicit ReplayWindow(size_t window = 256) : _window(window) {}

    bool contains(uint64_t seq) const {
        return _seen.count(seq) != 0;
    }

    void remember(uint64_t seq) {
        if (_seen.count(seq))
            return;
        _seen.insert(seq);
        _order.push_back(seq);
        if (_order.size() > _window) {
            _seen.erase(_order.front());
            _order.pop_front();
        }
    }

    bool accept(uint64_t seq) {
        if (_seen.count(seq))
            return false;
        remember(seq);
        return true;
    }

  private:
    size_t _window;
    std::unordered_set<uint64_t> _seen;
    std::deque<uint64_t> _order;
};

}  // namespace protocol::replay