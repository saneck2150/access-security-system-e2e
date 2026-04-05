//! @file s2_tamper.cpp
//! S2 Tamper scenario: modify door_id in serialized frame (without re-encrypting).
//! Expected: R0/R1 → decrypt_failed (AEAD tag mismatch); R2 → quarantine nonce_mismatch.

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S2Tamper final : public IScenario {
  public:
    std::string name() const override { return "S2_tamper"; }
    RunConfig config() const override { return {}; }

    void setup(ExperimentContext& ctx, FrameFactory& /*factory*/,
        const key_manager::KeyManager& /*km*/,
        const ProfileConfig& /*profile*/) override {
        // Register tampered door so binding check passes — AEAD catches it.
        ctx.allowDoorForReader(1, 7 + 999);
    }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = tc.trialSeqStart + idx;
        auto frame = factory.buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
        return FrameFactory::tamperDoorId(frame, cfg.doorId + 999);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S2Tamper scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s2_tamper.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S2] Done. Output: results/s2_tamper.csv\n";
    return 0;
}
