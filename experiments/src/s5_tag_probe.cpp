//! @file s5_tag_probe.cpp
//! S5 Tag Probe scenario: send frames with garbage ciphertext.
//! Expected: R0/R1 → decrypt_failed every time; R2 → quarantine after streak_limit (5).

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S5TagProbe final : public IScenario {
  public:
    std::string name() const override { return "S5_tag_probe"; }
    RunConfig config() const override { return {}; }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = tc.trialSeqStart + idx;
        auto frame = factory.buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
        return FrameFactory::tamperCiphertext(frame);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S5TagProbe scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s5_tag_probe.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S5] Done. Output: results/s5_tag_probe.csv\n";
    return 0;
}
