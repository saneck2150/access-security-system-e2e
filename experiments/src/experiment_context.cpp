#include "experiments/experiment_context.hpp"

#include <stdexcept>

namespace experiments {

ExperimentContext::ExperimentContext(const ProfileConfig& profile,
    const key_manager::KeyManager::MasterKey& masterKey,
    const std::string& dbPath,
    uint32_t readerId, uint32_t doorId,
    uint32_t keyVersion,
    const std::vector<std::string>& cardIds)
    : _km(masterKey, {.currentKeyVersion = keyVersion, .allowPreviousKeyVersion = true}),
      _hasher(_km.deriveCardPepper(keyVersion)),
      _events(64),
      _detector(access_core::DetectorConfig{
          .enabled = profile.detectorEnabled,
          .rollbackThreshold = profile.rollbackThreshold,
          .tagFailStreakLimit = profile.tagFailStreakLimit}) {
    // Create SQLite store.
    _store = std::make_unique<access_storage::SqliteAccessStore>(dbPath);
    _store->initSchema();

    // Register reader and door binding.
    _store->upsertReader(readerId, keyVersion);
    _store->allowDoorForReader(readerId, doorId);

    // Register cards with "employee" role and allow role on door.
    for (const auto& cardId : cardIds) {
        _store->upsertCardHmac(_hasher.hmacHex(cardId), "employee");
    }
    _store->allowRole(doorId, "employee");

    // Build FrameHandlerConfig and create engine.
    auto fhCfg = buildFhConfig(profile);
    _engine = std::make_unique<access_decision::DecisionEngine>(
        _store.get(), _hasher, &_audit, _km, fhCfg, &_events, &_detector);
}

access_decision::DecisionResult ExperimentContext::processFrame(
    std::span<const uint8_t> frameBytes) {
    return _engine->handleFrameBytes(frameBytes, _replayWindows);
}

bool ExperimentContext::isQuarantined(uint32_t readerId) const {
    return _detector.isQuarantined(readerId);
}

std::string ExperimentContext::quarantineAnomalyType(uint32_t readerId) const {
    auto info = _detector.quarantineInfo(readerId);
    if (!info) {
        return "";
    }
    return access_core::anomalyTypeToString(info->reason);
}

void ExperimentContext::allowDoorForReader(uint32_t readerId, uint32_t doorId) {
    _store->allowDoorForReader(readerId, doorId);
    _store->allowRole(doorId, "employee");
}

void ExperimentContext::resetState(uint32_t readerId) {
    _replayWindows.clear();
    _detector.unquarantine(readerId);
}

access_core::FrameHandlerConfig ExperimentContext::buildFhConfig(
    const ProfileConfig& profile) {
    access_core::FrameHandlerConfig cfg;
    cfg.antiReplayEnabled = true;
    cfg.replayWindowSize = 256;
    cfg.maxCtLen = 4096;
    cfg.maxSkewMs = 0;  // Disabled for experiments.
    cfg.allowPreviousKeyVersion = true;
    cfg.enforceReaderDoorBinding = true;
    cfg.keyDerivationMode = profile.keyDerivationMode;
    cfg.aadMode = profile.aadMode;
    cfg.pepperMode = profile.pepperMode;
    cfg.cipherMode = profile.cipherMode;
    cfg.nonceMode = profile.nonceMode;
    return cfg;
}

}  // namespace experiments
