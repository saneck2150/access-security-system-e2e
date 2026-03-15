#pragma once

//! @file protocol_anomaly_detector.hpp
//! R2 runtime anomaly detection with per-reader quarantine.

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace access_core {

//! Types of protocol anomalies detected by the runtime monitor.
enum class AnomalyType : uint8_t {
    seq_reuse,        //!< Same sequence number seen twice from one reader.
    seq_rollback,     //!< Sequence far below highest seen (possible key compromise).
    nonce_mismatch,   //!< Received nonce differs from expected HMAC-derived nonce.
    tag_fail_streak,  //!< Too many consecutive AEAD authentication failures.
};

//! Returns a human-readable string for an anomaly type.
//! @param [in] t Anomaly type.
//! @return String representation (e.g., "seq_reuse").
const char* anomalyTypeToString(AnomalyType t);

//! Configuration for the ProtocolAnomalyDetector.
struct DetectorConfig {
    bool enabled = false;               //!< Master switch (true only for R2 profiles).
    uint64_t rollbackThreshold = 100;   //!< Seq gap triggering seq_rollback quarantine.
    uint32_t tagFailStreakLimit = 5;     //!< Consecutive AEAD failures before quarantine.
};

//! Information about a quarantined reader.
struct QuarantineInfo {
    uint64_t ts_unix_ms = 0;  //!< When the reader was quarantined.
    AnomalyType reason{};     //!< Which anomaly triggered quarantine.
    std::string detail;       //!< Additional context (e.g., "seq=42 maxSeen=999").
};

//! Per-reader runtime anomaly detection and quarantine (R2 mode).
//!
//! Tracks sequence patterns, nonce correctness, and decryption failures.
//! When anomaly thresholds are exceeded, the reader is quarantined —
//! all subsequent frames are denied until an admin explicitly unquarantines.
//!
//! Thread-safe: all public methods acquire an internal mutex.
class ProtocolAnomalyDetector {
  public:
    explicit ProtocolAnomalyDetector(DetectorConfig config = {});

    //! Checks if a reader is currently quarantined.
    //! @param [in] readerId Reader to check.
    //! @return True if quarantined.
    bool isQuarantined(uint32_t readerId) const;

    //! Returns quarantine details for a reader.
    //! @param [in] readerId Reader to query.
    //! @return QuarantineInfo if quarantined, nullopt otherwise.
    std::optional<QuarantineInfo> quarantineInfo(uint32_t readerId) const;

    //! Reports a replay detection (seq already seen by ReplayWindow).
    //! Immediately quarantines the reader.
    //! @param [in] readerId Reader that sent the replayed frame.
    //! @param [in] seq      The replayed sequence number.
    //! @param [in] tsMs     Current timestamp.
    //! @return seq_reuse anomaly type.
    AnomalyType reportReplay(uint32_t readerId, uint64_t seq, uint64_t tsMs);

    //! Reports a received sequence number for rollback analysis.
    //! Quarantines if seq < maxSeen - rollbackThreshold.
    //! @param [in] readerId Reader ID.
    //! @param [in] seq      Frame sequence number.
    //! @param [in] tsMs     Current timestamp.
    //! @return seq_rollback if triggered, nullopt otherwise.
    std::optional<AnomalyType> reportSeq(uint32_t readerId, uint64_t seq, uint64_t tsMs);

    //! Reports a nonce mismatch (received != expected HMAC nonce).
    //! Immediately quarantines the reader.
    //! @param [in] readerId Reader ID.
    //! @param [in] tsMs     Current timestamp.
    //! @return nonce_mismatch anomaly type.
    AnomalyType reportNonceMismatch(uint32_t readerId, uint64_t tsMs);

    //! Reports an AEAD authentication failure.
    //! Quarantines after tagFailStreakLimit consecutive failures.
    //! @param [in] readerId Reader ID.
    //! @param [in] tsMs     Current timestamp.
    //! @return tag_fail_streak if threshold exceeded, nullopt otherwise.
    std::optional<AnomalyType> reportTagFailure(uint32_t readerId, uint64_t tsMs);

    //! Reports a successful frame processing.
    //! Resets the tag failure streak and updates maxSeenSeq.
    //! @param [in] readerId Reader ID.
    //! @param [in] seq      Successfully processed sequence number.
    void reportSuccess(uint32_t readerId, uint64_t seq);

    //! Removes quarantine for a reader (admin action).
    //! Also resets the tag failure streak.
    //! @param [in] readerId Reader to unquarantine.
    //! @return True if the reader was quarantined, false if it wasn't.
    bool unquarantine(uint32_t readerId);

    //! Compares received nonce with expected nonce (constant-time).
    //! @param [in] received Nonce from the frame header.
    //! @param [in] expected Nonce computed by HmacNonceGenerator.
    //! @param [in] len      Effective nonce length (12 or 24).
    //! @return True if nonces match.
    static bool nonceEqual(
        const std::array<uint8_t, 24>& received,
        const std::array<uint8_t, 24>& expected,
        size_t len);

    //! @return Detector configuration.
    const DetectorConfig& config() const { return _config; }

  private:
    DetectorConfig _config;
    mutable std::mutex _m;

    //! Per-reader tracked state.
    struct ReaderState {
        uint64_t maxSeenSeq = 0;           //!< Highest sequence number observed.
        uint32_t consecutiveTagFails = 0;  //!< Current AEAD failure streak.
        std::optional<QuarantineInfo> quarantine;  //!< Set when quarantined.
    };

    std::unordered_map<uint32_t, ReaderState> _readers;

    //! Gets or creates state for a reader. Caller must hold _m.
    ReaderState& getState(uint32_t readerId);

    //! Quarantines a reader. Caller must hold _m.
    void doQuarantine(
        ReaderState& state, AnomalyType reason, uint64_t tsMs, std::string detail);
};

}  // namespace access_core
