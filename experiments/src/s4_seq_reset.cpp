//! @file s4_seq_reset.cpp
//! S4 Seq Reset scenario: send frames with seq far below maxSeen.
//! R0/R1: frame passes (replay window + decryption succeed). R2: quarantine seq_rollback.

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S4SeqReset final : public IScenario {
    static constexpr uint64_t kRollbackThreshold = 100;
    static constexpr size_t kWindowSize = 256;

  public:
    std::string name() const override { return "S4_seq_reset"; }

    RunConfig config() const override {
        RunConfig cfg;
        cfg.warmupSeqStart = 50000;
        cfg.baselineSeqStart = 60000;
        return cfg;
    }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        // Rollback zone: [tooOldFloor, rollbackCeiling) — not too old, not seen, triggers rollback.
        const uint64_t rollbackCeiling = tc.maxSeenSeq - kRollbackThreshold;
        const uint64_t tooOldFloor = tc.maxSeenSeq - kWindowSize + 1;
        const uint64_t rollbackSlots = rollbackCeiling - tooOldFloor;
        uint64_t seq = tooOldFloor + (idx % rollbackSlots);

        return factory.buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S4SeqReset scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s4_seq_reset.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S4] Done. Output: results/s4_seq_reset.csv\n";
    return 0;
}
