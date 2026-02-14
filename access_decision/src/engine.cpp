#include "access_decision/engine.hpp"

#include <string_view>

namespace access_decision {

DecisionEngine::DecisionEngine(const IAccessStore* store, CardIdHasher hasher, IAuditLog* audit,
                               access_core::FrameHandlerConfig frameHandlerCfg)
    : _store(store), _hasher(std::move(hasher)), _audit(audit), _frameHandlerCfg(frameHandlerCfg) {}

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
}

DecisionResult DecisionEngine::createDeniedResult(const std::string& reason) {
    DecisionResult result;
    result.allow = false;
    result.reason = reason;
    return result;
}

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

    const auto cardHmac = _hasher.hmacHex(request.cardId);
    const auto roleOpt = _store->roleForCardHmac(cardHmac);

    if (!roleOpt.has_value()) {
        result = createDeniedResult("unknown_card");
    } else if (!_store->isAllowed(frameResult.header.door_id, *roleOpt)) {
        result = createDeniedResult("forbidden");
    } else {
        result.allow = true;
        result.reason = "ok";
    }

    logAuditEvent(frameResult.header, result.allow, result.reason, cardHmac, request.action);
    return result;
}

DecisionResult DecisionEngine::handleFrameBytes(
    std::span<const uint8_t> frameBytes, crypto_lib::aead::SecureAead& serverAead,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader) {
    access_core::FrameHandler handler(serverAead, replayByReader, _frameHandlerCfg);
    const auto frameResult = handler.handle(frameBytes);

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
