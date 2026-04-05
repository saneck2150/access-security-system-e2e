#include "access_decision/engine.hpp"

#include <chrono>
#include <string_view>

#include <access_core/protocol_anomaly_detector.hpp>
#include <crypto_lib/nonce_generator.hpp>
#include <runtime_events/event_bus.hpp>

namespace access_decision {

uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

DecisionEngine::DecisionEngine(const IAccessStore* store,
    CardIdHasher hasher,
    IAuditLog* audit,
    const key_manager::KeyManager& keyManager,
    access_core::FrameHandlerConfig frameHandlerCfg,
    runtime_events::EventBus* events,
    access_core::ProtocolAnomalyDetector* detector)
    : _store(store),
      _hasher(std::move(hasher)),
      _audit(audit),
      _keyManager(keyManager),
      _frameHandlerCfg(frameHandlerCfg),
      _events(events),
      _detector(detector) {}

void DecisionEngine::logAuditEvent(const protocol::packet::Header& header,
    bool allow,
    const std::string& reason,
    const std::string& cardId,
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

void DecisionEngine::publishFrameEvent(size_t frameSize) {
    if (!_events) {
        return;
    }

    runtime_events::Event ev;
    ev.ts_unix_ms = nowUnixMs();
    ev.kind = "frame";
    ev.message = "frame received, bytes=" + std::to_string(frameSize);
    _events->push(std::move(ev));
}

void DecisionEngine::publishDecisionEvent(const access_core::HandleResult& frameResult) {
    if (!_events) {
        return;
    }

    runtime_events::Event ev;
    ev.ts_unix_ms = nowUnixMs();
    ev.kind = "decision";
    ev.reader_id = frameResult.header.reader_id;
    ev.door_id = frameResult.header.door_id;
    ev.seq = frameResult.header.seq;
    ev.allow = frameResult.allow;
    ev.reason = frameResult.reason;
    ev.message = std::string("frame handler: ") + (frameResult.allow ? "ALLOW " : "DENY ") +
                 frameResult.reason;
    _events->push(std::move(ev));
}

std::string DecisionEngine::resolveCardHmac(
    const std::string& cardId, uint32_t currentKv, std::optional<std::string>& roleOut) {
    // Static pepper mode: always use key version 1, no rotation.
    if (_frameHandlerCfg.pepperMode == "static") {
        const auto pepper = _keyManager.deriveCardPepper(1);
        CardIdHasher hasher(pepper);
        const std::string cardHmac = hasher.hmacHex(cardId);
        roleOut = _store->roleForCardHmac(cardHmac);
        return cardHmac;
    }

    // Default versioned mode with optional rotation support.
    const auto pepperCur = _keyManager.deriveCardPepper(currentKv);
    CardIdHasher hasherCur(pepperCur);
    std::string cardHmac = hasherCur.hmacHex(cardId);

    roleOut = _store->roleForCardHmac(cardHmac);

    if (!roleOut.has_value() && _frameHandlerCfg.allowPreviousKeyVersion && currentKv > 1) {
        const auto pepperPrev = _keyManager.deriveCardPepper(currentKv - 1);
        CardIdHasher hasherPrev(pepperPrev);
        const std::string cardHmacPrev = hasherPrev.hmacHex(cardId);

        roleOut = _store->roleForCardHmac(cardHmacPrev);
        if (roleOut.has_value()) {
            cardHmac = cardHmacPrev;
        }
    }

    return cardHmac;
}

DecisionResult DecisionEngine::checkRoleAccess(uint32_t doorId, const std::string& role) {
    DecisionResult result;
    if (!_store->isAllowed(doorId, role)) {
        result.allow = false;
        result.reason = "forbidden";
    } else {
        result.allow = true;
        result.reason = "ok";
    }
    return result;
}

DecisionResult DecisionEngine::checkAccessPolicy(
    const access_core::HandleResult& frameResult, const AccessRequest& request) {
    if (request.action != "open") {
        const auto res = createDeniedResult("bad_action");
        logAuditEvent(frameResult.header, false, res.reason);
        return res;
    }

    if (!_store) {
        const auto res = createDeniedResult("no_store");
        logAuditEvent(frameResult.header, false, res.reason);
        return res;
    }

    const uint32_t currentKv = _store->currentKeyVersionForReader(frameResult.header.reader_id);
    if (currentKv == 0) {
        const auto res = createDeniedResult("unknown_reader");
        logAuditEvent(frameResult.header, false, res.reason);
        return res;
    }

    std::optional<std::string> roleOpt;
    const std::string cardHmac = resolveCardHmac(request.cardId, currentKv, roleOpt);

    if (!roleOpt.has_value()) {
        const auto res = createDeniedResult("unknown_card");
        logAuditEvent(frameResult.header, false, res.reason, cardHmac, request.action);
        return res;
    }

    const auto result = checkRoleAccess(frameResult.header.door_id, *roleOpt);
    logAuditEvent(frameResult.header, result.allow, result.reason, cardHmac, request.action);
    return result;
}

void DecisionEngine::publishAnomalyEvent(
    uint32_t readerId, access_core::AnomalyType type, const std::string& detail) {
    if (!_events) {
        return;
    }
    runtime_events::Event ev;
    ev.ts_unix_ms = nowUnixMs();
    ev.kind = "anomaly";
    ev.reader_id = readerId;
    ev.message = std::string("anomaly: ") + access_core::anomalyTypeToString(type);
    if (!detail.empty()) {
        ev.message += " " + detail;
    }
    ev.reason = access_core::anomalyTypeToString(type);
    _events->push(std::move(ev));
}

DecisionResult DecisionEngine::handleFrameBytes(std::span<const uint8_t> frameBytes,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader) {
    access_core::FrameHandler handler(_keyManager, replayByReader, _store, _frameHandlerCfg);
    const auto frameResult = handler.handle(frameBytes);
    const uint32_t readerId = frameResult.header.reader_id;
    const bool detectorActive = _detector && _detector->config().enabled;

    publishFrameEvent(frameBytes.size());

    // R2: check quarantine before any further processing.
    if (detectorActive && _detector->isQuarantined(readerId)) {
        logAuditEvent(frameResult.header, false, "quarantined");
        publishDecisionEvent(frameResult);
        return createDeniedResult("quarantined");
    }

    // R2: check sequence rollback.
    if (detectorActive && frameResult.header.seq > 0) {
        if (auto anomaly = _detector->reportSeq(readerId, frameResult.header.seq, nowUnixMs())) {
            publishAnomalyEvent(readerId, *anomaly, "");
            logAuditEvent(frameResult.header, false, "quarantined");
            publishDecisionEvent(frameResult);
            return createDeniedResult("quarantined");
        }
    }

    // R2: verify deterministic nonce matches expected value.
    if (detectorActive && _frameHandlerCfg.nonceMode == "deterministic") {
        const auto nonceKey = _keyManager.deriveNonceKey(
            readerId, frameResult.header.key_version);
        const auto cm = (_frameHandlerCfg.cipherMode == "chacha20")
                            ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                            : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
        crypto_lib::nonce::HmacNonceGenerator gen(nonceKey, cm);

        // Build context: header fields with nonce zeroed.
        protocol::packet::Header ctxHeader = frameResult.header;
        ctxHeader.nonce = {};
        const auto context = ctxHeader.to_bytes();

        const auto expected = gen.generate(context, frameResult.header.seq);
        const size_t nonceLen = crypto_lib::nonce::nonceLenFor(cm);

        if (!access_core::ProtocolAnomalyDetector::nonceEqual(
                frameResult.header.nonce, expected, nonceLen)) {
            _detector->reportNonceMismatch(readerId, nowUnixMs());
            publishAnomalyEvent(readerId, access_core::AnomalyType::nonce_mismatch, "");
            logAuditEvent(frameResult.header, false, "quarantined");
            publishDecisionEvent(frameResult);
            return createDeniedResult("quarantined");
        }
    }

    publishDecisionEvent(frameResult);

    if (!frameResult.allow) {
        // R2: track replay and tag failures.
        if (detectorActive) {
            if (frameResult.reason == "replay") {
                auto anomaly = _detector->reportReplay(
                    readerId, frameResult.header.seq, nowUnixMs());
                publishAnomalyEvent(readerId, anomaly, "");
            } else if (frameResult.reason == "mac_verification_failed" ||
                       frameResult.reason == "decrypt_failed") {
                if (auto anomaly = _detector->reportTagFailure(readerId, nowUnixMs())) {
                    publishAnomalyEvent(readerId, *anomaly, "");
                }
            }
        }
        logAuditEvent(frameResult.header, false, frameResult.reason);
        return createDeniedResult(frameResult.reason);
    }

    // Success: reset tag failure streak.
    if (detectorActive) {
        _detector->reportSuccess(readerId, frameResult.header.seq);
    }

    std::string_view plaintext(
        reinterpret_cast<const char*>(frameResult.plaintext.data()), frameResult.plaintext.size());

    AccessRequest request;
    try {
        request = parseAccessRequestJson(plaintext);
    } catch (...) {
        logAuditEvent(frameResult.header, false, "bad_payload");
        return createDeniedResult("bad_payload");
    }

    return checkAccessPolicy(frameResult, request);
}

}  // namespace access_decision
