#pragma once

//! @file audit.hpp
//! Audit logging interface and in-memory implementation.

#include <cstdint>
#include <string>
#include <vector>

namespace access_decision {

//! Represents a single access decision event for audit logging.
struct AuditEvent {
    //! Unix timestamp in milliseconds.
    uint64_t ts_unix_ms = 0;
    //! Reader that received the request.
    uint32_t reader_id = 0;
    //! Door the request was for.
    uint32_t door_id = 0;
    //! Sequence number (replay protection).
    uint64_t seq = 0;
    //! True if access was granted.
    bool allow = false;
    //! Outcome code (e.g., "ok", "forbidden").
    std::string reason;
    //! HMAC-hashed card identifier.
    std::string card_id;
    //! Requested action (e.g., "open").
    std::string action;
};

//! Abstract interface for audit logging.
class IAuditLog {
  public:
    virtual ~IAuditLog() = default;

    //! Appends an audit event to the log.
    //! @param [in] e The event to log.
    virtual void append(AuditEvent e) = 0;
};

//! Simple in-memory audit log for testing.
class InMemoryAuditLog final : public IAuditLog {
  public:
    void append(AuditEvent e) override { _events.push_back(std::move(e)); }

    //! Returns all logged events.
    const std::vector<AuditEvent>& events() const { return _events; }

  private:
    std::vector<AuditEvent> _events;
};

}  // namespace access_decision
