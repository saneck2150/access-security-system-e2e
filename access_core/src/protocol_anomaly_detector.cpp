#include "access_core/protocol_anomaly_detector.hpp"

#include <sodium.h>

namespace access_core {

const char* anomalyTypeToString(AnomalyType t) {
    switch (t) {
        case AnomalyType::seq_reuse: return "seq_reuse";
        case AnomalyType::seq_rollback: return "seq_rollback";
        case AnomalyType::nonce_mismatch: return "nonce_mismatch";
        case AnomalyType::tag_fail_streak: return "tag_fail_streak";
    }
    return "unknown";
}

ProtocolAnomalyDetector::ProtocolAnomalyDetector(DetectorConfig config) : _config(config) {}

ProtocolAnomalyDetector::ReaderState& ProtocolAnomalyDetector::getState(uint32_t readerId) {
    return _readers[readerId];
}

void ProtocolAnomalyDetector::doQuarantine(
    ReaderState& state, AnomalyType reason, uint64_t tsMs, std::string detail) {
    state.quarantine = QuarantineInfo{
        .ts_unix_ms = tsMs, .reason = reason, .detail = std::move(detail)};
}

bool ProtocolAnomalyDetector::isQuarantined(uint32_t readerId) const {
    std::lock_guard<std::mutex> lk(_m);
    auto it = _readers.find(readerId);
    if (it == _readers.end()) {
        return false;
    }
    return it->second.quarantine.has_value();
}

std::optional<QuarantineInfo> ProtocolAnomalyDetector::quarantineInfo(uint32_t readerId) const {
    std::lock_guard<std::mutex> lk(_m);
    auto it = _readers.find(readerId);
    if (it == _readers.end()) {
        return std::nullopt;
    }
    return it->second.quarantine;
}

AnomalyType ProtocolAnomalyDetector::reportReplay(
    uint32_t readerId, uint64_t seq, uint64_t tsMs) {
    std::lock_guard<std::mutex> lk(_m);
    auto& state = getState(readerId);
    doQuarantine(state, AnomalyType::seq_reuse, tsMs, "seq=" + std::to_string(seq));
    return AnomalyType::seq_reuse;
}

std::optional<AnomalyType> ProtocolAnomalyDetector::reportSeq(
    uint32_t readerId, uint64_t seq, uint64_t tsMs) {
    std::lock_guard<std::mutex> lk(_m);
    auto& state = getState(readerId);

    if (state.maxSeenSeq > 0 && seq + _config.rollbackThreshold < state.maxSeenSeq) {
        doQuarantine(state, AnomalyType::seq_rollback, tsMs,
            "seq=" + std::to_string(seq) + " maxSeen=" + std::to_string(state.maxSeenSeq));
        return AnomalyType::seq_rollback;
    }

    if (seq > state.maxSeenSeq) {
        state.maxSeenSeq = seq;
    }
    return std::nullopt;
}

AnomalyType ProtocolAnomalyDetector::reportNonceMismatch(uint32_t readerId, uint64_t tsMs) {
    std::lock_guard<std::mutex> lk(_m);
    auto& state = getState(readerId);
    doQuarantine(state, AnomalyType::nonce_mismatch, tsMs, "");
    return AnomalyType::nonce_mismatch;
}

std::optional<AnomalyType> ProtocolAnomalyDetector::reportTagFailure(
    uint32_t readerId, uint64_t tsMs) {
    std::lock_guard<std::mutex> lk(_m);
    auto& state = getState(readerId);
    ++state.consecutiveTagFails;

    if (state.consecutiveTagFails >= _config.tagFailStreakLimit) {
        doQuarantine(state, AnomalyType::tag_fail_streak, tsMs,
            "streak=" + std::to_string(state.consecutiveTagFails));
        return AnomalyType::tag_fail_streak;
    }
    return std::nullopt;
}

void ProtocolAnomalyDetector::reportSuccess(uint32_t readerId, uint64_t seq) {
    std::lock_guard<std::mutex> lk(_m);
    auto& state = getState(readerId);
    state.consecutiveTagFails = 0;
    if (seq > state.maxSeenSeq) {
        state.maxSeenSeq = seq;
    }
}

bool ProtocolAnomalyDetector::unquarantine(uint32_t readerId) {
    std::lock_guard<std::mutex> lk(_m);
    auto it = _readers.find(readerId);
    if (it == _readers.end() || !it->second.quarantine.has_value()) {
        return false;
    }
    it->second.quarantine.reset();
    it->second.consecutiveTagFails = 0;
    return true;
}

bool ProtocolAnomalyDetector::nonceEqual(
    const std::array<uint8_t, 24>& received,
    const std::array<uint8_t, 24>& expected,
    size_t len) {
    return sodium_memcmp(received.data(), expected.data(), len) == 0;
}

}  // namespace access_core
