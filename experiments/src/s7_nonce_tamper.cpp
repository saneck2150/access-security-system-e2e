//! @file s7_nonce_tamper.cpp
//! S7 Nonce Tamper scenario: simulates MITM attack that modifies nonce in transit.
//!   A valid frame is built, then the nonce in the header is XOR-flipped.
//!   AEAD decryption fails (wrong keystream + tag mismatch) for all profiles.
//!   R2 additionally: nonce_mismatch detected before AEAD → immediate quarantine.

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S7NonceTamper final : public IScenario {
  public:
    std::string name() const override { return "S7_nonce_tamper"; }
    RunConfig config() const override { return {}; }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = tc.trialSeqStart + idx;
        auto frame = factory.buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
        // Simulate MITM: tamper the nonce in a valid frame after it was built.
        return FrameFactory::tamperNonce(frame);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S7NonceTamper scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s7_nonce_tamper.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S7] Done. Output: results/s7_nonce_tamper.csv\n";
    return 0;
}
