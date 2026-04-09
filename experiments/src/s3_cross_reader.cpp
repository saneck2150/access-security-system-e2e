//! @file s3_cross_reader.cpp
//! S3b — Cross-Reader HKDF Key Isolation (component validation):
//!   Frame encrypted with reader_2's HKDF-derived key, header tampered to reader_1.
//!   Verifies that HKDF per-reader key derivation prevents cross-reader acceptance.
//! Expected: all profiles → decrypt_failed (HKDF isolation).
//!   R2 additionally: immediate quarantine via nonce_mismatch (nonce context mismatch).
//!
//! This is NOT a simulation of the production HTTP pipeline (reader does not build
//! AEAD frames). It is a component-level validation of HKDF key compartmentalization.

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S3bCrossReader final : public IScenario {
  public:
    std::string name() const override { return "S3b_cross_reader"; }
    RunConfig config() const override { return {}; }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = tc.trialSeqStart + idx;
        // Encrypt frame with a different reader's HKDF-derived key context.
        // Simulates a compromised component that has reader_2's key material
        // and attempts to impersonate the legitimate reader_1.
        constexpr uint32_t kCompromisedReaderId = 2;
        auto frame = factory.buildFrame(kCompromisedReaderId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
        // Tamper header to claim the legitimate reader (cfg.readerId = 1).
        // Engine derives key for reader_1 → AEAD decrypt fails (wrong key + wrong AAD).
        return FrameFactory::tamperReaderId(frame, cfg.readerId);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S3bCrossReader scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s3_cross_reader.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S3b] Done. Output: results/s3_cross_reader.csv\n";
    return 0;
}
