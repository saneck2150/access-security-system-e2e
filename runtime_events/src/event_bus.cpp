#include "runtime_events/event_bus.hpp"

namespace runtime_events {

EventBus::EventBus(size_t maxEvents) : _max(maxEvents) {}

uint64_t EventBus::push(Event e) {
    std::lock_guard<std::mutex> lk(_m);
    e.id = ++_lastId;
    if (_events.size() >= _max) {
        _events.pop_front();
    }
    _events.push_back(std::move(e));
    return _lastId;
}

std::vector<Event> EventBus::getAfter(uint64_t afterId, size_t limit) const {
    std::lock_guard<std::mutex> lk(_m);
    std::vector<Event> out;
    out.reserve(limit);

    for (const auto& e : _events) {
        if (e.id > afterId) {
            out.push_back(e);
            if (out.size() >= limit) {
                break;
            }
        }
    }
    return out;
}

uint64_t EventBus::lastId() const {
    std::lock_guard<std::mutex> lk(_m);
    return _lastId;
}

}  // namespace runtime_events
