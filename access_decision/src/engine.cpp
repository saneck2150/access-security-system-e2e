#include "access_decision/engine.hpp"

#include <runtime_events/event_bus.hpp>

#include <string_view>
#include <chrono>

namespace access_decision {

uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

DecisionEngine::DecisionEngine(const IAccessStore* store, CardIdHasher hasher, IAuditLog* audit,
                               const key_manager::KeyManager& keyManager,
                               access_core::FrameHandlerConfig frameHandlerCfg,
                               runtime_events::EventBus* events)
    : _store(store),
      _hasher(std::move(hasher)),
      _audit(audit),
      _keyManager(keyManager),
      _frameHandlerCfg(frameHandlerCfg),
      _events(events) {}

void DecisionEngine::logAuditEvent(const protocol::packet::Header& header, bool allow,
                                   const std::string& reason, const std::string& cardId,
                                   const std::string& action) {
    if (!_audit) {
        return;
    }
    AuditEvent event;
    event.ts_unix_ms = header.ts_unix_ms;
    event.reader_id = header.reader_id;
    event.door_id = header.door_id;
    event.seq = header.seq;
    event.allow = allow;
    event.reason = reason;
    event.card_id = cardId;
    event.action = action;
    _audit->append(std::move(event));
    
    if (_events) {
        runtime_events::Event ev;
        ev.ts_unix_ms = nowUnixMs();
        ev.kind = "audit";
        ev.message = std::string("audit append: ") + (allow ? "ALLOW " : "DENY ") + reason;
        ev.reader_id = header.reader_id;
        ev.door_id = header.door_id;
        ev.seq = header.seq;
        ev.allow = allow;
        ev.reason = reason;
        _events->push(std::move(ev));
    }
}

DecisionResult DecisionEngine::createDeniedResult(const std::string& reason) {
    DecisionResult result;
    result.allow = false;
    result.reason = reason;
    return result;
}

///@todo: split into smaller functions + move buss to new file
DecisionResult DecisionEngine::checkAccessPolicy(const access_core::HandleResult& frameResult,
                                                 const AccessRequest& request) {
    DecisionResult result;

    if (request.action != "open") {
        result = createDeniedResult("bad_action");
        logAuditEvent(frameResult.header, false, result.reason);
        return result;
    }

    if (!_store) {
        result = createDeniedResult("no_store");
        logAuditEvent(frameResult.header, false, result.reason);
        return result;
    }

    const uint32_t currentKv = _store->currentKeyVersionForReader(frameResult.header.reader_id);
    if (currentKv == 0) {
        const auto res = createDeniedResult("unknown_reader");
        logAuditEvent(frameResult.header, false, res.reason);
        return res;
    }

    const auto pepperCur = _keyManager.deriveCardPepper(currentKv);
    access_decision::CardIdHasher hasherCur(pepperCur);

    std::string cardHmac = hasherCur.hmacHex(request.cardId);
    auto roleOpt = _store->roleForCardHmac(cardHmac);

    if (!roleOpt.has_value() && _frameHandlerCfg.allowPreviousKeyVersion && currentKv > 1) {
        const auto pepperPrev = _keyManager.deriveCardPepper(currentKv - 1);
        access_decision::CardIdHasher hasherPrev(pepperPrev);
        const std::string cardHmacPrev = hasherPrev.hmacHex(request.cardId);

        roleOpt = _store->roleForCardHmac(cardHmacPrev);
        if (roleOpt.has_value()) {
            cardHmac = cardHmacPrev; // audit will log the found one
        }
    }

    if (!roleOpt.has_value()) {
        const auto res = createDeniedResult("unknown_card");
        logAuditEvent(frameResult.header, false, res.reason, cardHmac, request.action);
        return res;
    }

    if (!_store->isAllowed(frameResult.header.door_id, *roleOpt)) {
        result = createDeniedResult("forbidden");
    } else {
        result.allow = true;
        result.reason = "ok";
    }

    logAuditEvent(frameResult.header, result.allow, result.reason, cardHmac, request.action);
    return result;
}

///@todo split into smaller functions + move buss to new file
DecisionResult DecisionEngine::handleFrameBytes(
    std::span<const uint8_t> frameBytes,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader) {
    access_core::FrameHandler handler(_keyManager, replayByReader, _store, _frameHandlerCfg);
    const auto frameResult = handler.handle(frameBytes);
    
    if (_events) {
        runtime_events::Event ev;
        ev.ts_unix_ms = nowUnixMs();
        ev.kind = "frame";
        ev.message = "frame received, bytes=" + std::to_string(frameBytes.size());
        _events->push(std::move(ev));
    }

    if (_events) {
        runtime_events::Event ev;
        ev.ts_unix_ms = nowUnixMs();
        ev.kind = "decision";
        ev.reader_id = frameResult.header.reader_id;
        ev.door_id = frameResult.header.door_id;
        ev.seq = frameResult.header.seq;
        ev.allow = frameResult.allow;
        ev.reason = frameResult.reason;
        ev.message = std::string("frame handler: ") + (frameResult.allow ? "ALLOW " : "DENY ") + frameResult.reason;
        _events->push(std::move(ev));
    }

    if (!frameResult.allow) {
        logAuditEvent(frameResult.header, false, frameResult.reason);
        return createDeniedResult(frameResult.reason);
    }

    if (!frameResult.allow) {
        logAuditEvent(frameResult.header, false, frameResult.reason);
        return createDeniedResult(frameResult.reason);
    }

    std::string_view plaintext(reinterpret_cast<const char*>(frameResult.plaintext.data()),
                               frameResult.plaintext.size());

    AccessRequest request;
    try {
        request = parseAccessRequestJson(plaintext);
    } catch (...) {
        logAuditEvent(frameResult.header, false, "bad_payload");
        return createDeniedResult("bad_payload");
    }

    return checkAccessPolicy(frameResult, request);
}

} // namespace access_decision
