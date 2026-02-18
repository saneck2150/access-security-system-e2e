#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace runtime_events {

struct Event {
    uint64_t id = 0;
    uint64_t ts_unix_ms = 0;

    std::string kind;           // e.g. "frame", "decision", "audit", "admin"
    std::string message;        // human-readable

    uint32_t reader_id = 0;
    uint32_t door_id = 0;
    uint64_t seq = 0;

    bool allow = false;
    std::string reason;         // "ok", "replay", ...
};

class EventBus {
  public:
    explicit EventBus(size_t maxEvents = 1024) : _max(maxEvents) {}

    uint64_t push(Event e) {
        std::lock_guard<std::mutex> lk(_m);
        e.id = ++_lastId;
        if (_events.size() >= _max) {
            _events.pop_front();
        }
        _events.push_back(std::move(e));
        return _lastId;
    }

    std::vector<Event> getAfter(uint64_t afterId, size_t limit = 200) const {
        std::lock_guard<std::mutex> lk(_m);
        std::vector<Event> out;
        out.reserve(limit);

        for (const auto& e : _events) {
            if (e.id > afterId) {
                out.push_back(e);
                if (out.size() >= limit) break;
            }
        }
        return out;
    }

    uint64_t lastId() const {
        std::lock_guard<std::mutex> lk(_m);
        return _lastId;
    }

  private:
    size_t _max = 1024;

    mutable std::mutex _m;
    std::deque<Event> _events;
    uint64_t _lastId = 0;
};

} // namespace runtime_events