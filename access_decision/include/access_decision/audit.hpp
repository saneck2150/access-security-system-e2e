#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace access_decision {

struct AuditEvent {
    uint64_t ts_unix_ms = 0;
    uint32_t reader_id = 0;
    uint32_t door_id = 0;
    uint64_t seq = 0;

    bool allow = false;
    std::string reason;

    std::string card_id;
    std::string action;
};

class IAuditLog {
  public:
    virtual ~IAuditLog() = default;
    virtual void append(AuditEvent e) = 0;
};

class InMemoryAuditLog final : public IAuditLog {
  public:
    void append(AuditEvent e) override {
        _events.push_back(std::move(e));
    }
    const std::vector<AuditEvent>& events() const {
        return _events;
    }

  private:
    std::vector<AuditEvent> _events;
};

}  // namespace access_decision
