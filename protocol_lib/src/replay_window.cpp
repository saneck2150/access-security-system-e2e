#include "protocol_lib/replay_window.hpp"

using namespace protocol::replay;

ReplayWindow::ReplayWindow(size_t window) : _window(window) {}

bool ReplayWindow::isTooOld(uint64_t seq) const {
    if (_maxSeen == 0)
        return false;
    if (_maxSeen < _window)
        return false;
    return seq <= (_maxSeen - _window);
}

bool ReplayWindow::contains(uint64_t seq) const {
    return isTooOld(seq) || (_seen.count(seq) != 0);
}

bool ReplayWindow::isAlreadySeen(uint64_t seq) const {
    return _seen.count(seq) != 0;
}

void ReplayWindow::evictOldestIfFull() {
    if (_order.size() > _window) {
        _seen.erase(_order.front());
        _order.pop_front();
    }
}

void ReplayWindow::remember(uint64_t seq) {
    if (contains(seq)) {
        return;
    }
    if (seq > _maxSeen) {
        _maxSeen = seq;
    }
    _seen.insert(seq);
    _order.push_back(seq);
    evictOldestIfFull();
}

bool ReplayWindow::accept(uint64_t seq) {
    if (contains(seq)) {
        return false;
    }
    remember(seq);
    return true;
}
