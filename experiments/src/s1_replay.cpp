//! @file s1_replay.cpp
//! S1 Replay scenario: repeat a valid frame multiple times.
//! Expected: R0/R1 deny "replay"; R2 deny + quarantine "seq_reuse".

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S1Replay final : public IScenario {
    std::vector<uint8_t> _captured;

  public:
    std::string name() const override { return "S1_replay"; }
    RunConfig config() const override { return {}; }

    void setup(ExperimentContext& /*ctx*/, FrameFactory& /*factory*/,
        const key_manager::KeyManager& /*km*/,
        const ProfileConfig& /*profile*/) override {
        _captured.clear();
    }

    void onBaselineFrame(uint32_t idx, uint32_t total,
        const std::vector<uint8_t>& frame) override {
        if (idx == total / 2) {
            _captured = frame;
        }
    }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& /*factory*/, const RunConfig& /*cfg*/,
        const TrialContext& /*tc*/, uint32_t /*idx*/, uint32_t /*stepN*/) override {
        return _captured;
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S1Replay scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s1_replay.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S1] Done. Output: results/s1_replay.csv\n";
    return 0;
}
