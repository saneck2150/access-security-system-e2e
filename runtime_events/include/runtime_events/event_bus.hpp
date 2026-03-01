#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace runtime_events {

//! Represents a single runtime event in the system.
struct Event {
    //! Unique auto-incremented event identifier.
    uint64_t id = 0;
    //! Unix timestamp in milliseconds when the event occurred.
    uint64_t ts_unix_ms = 0;

    //! Event category: "frame", "decision", "audit", or "admin".
    std::string kind;
    //! Human-readable event description.
    std::string message;

    //! Reader device identifier that triggered the event.
    uint32_t reader_id = 0;
    //! Door identifier associated with the event.
    uint32_t door_id = 0;
    //! Sequence number for replay detection.
    uint64_t seq = 0;

    //! True if access was granted, false if denied.
    bool allow = false;
    //! Reason code: "ok", "replay", "unknown_card", etc.
    std::string reason;
};

//! Thread-safe circular buffer for runtime events with configurable capacity.
class EventBus {
  public:
    //! Constructs an EventBus with specified maximum event capacity.
    //! @param maxEvents [in] Maximum number of events to retain (oldest dropped
    //! when full).
    explicit EventBus(size_t maxEvents = 1024);

    //! Adds an event to the bus, assigning it a unique ID.
    //! @param e [in] Event to push (id field will be overwritten).
    //! @return Assigned event ID.
    uint64_t push(Event e);

    //! Retrieves events with ID greater than afterId.
    //! @param afterId [in] Return only events with id > afterId.
    //! @param limit [in] Maximum number of events to return.
    //! @return Vector of matching events in chronological order.
    std::vector<Event> getAfter(uint64_t afterId, size_t limit = 200) const;

    //! Returns the ID of the most recently pushed event.
    //! @return Last assigned event ID, or 0 if no events pushed.
    uint64_t lastId() const;

  private:
    //! Maximum number of events to store before dropping oldest.
    size_t _max;
    //! Mutex for thread-safe access to event storage.
    mutable std::mutex _m;
    //! Circular buffer storing events.
    std::deque<Event> _events;
    //! Counter for generating unique event IDs.
    uint64_t _lastId = 0;
};

}  // namespace runtime_events
