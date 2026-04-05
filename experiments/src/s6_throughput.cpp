//! @file s6_throughput.cpp
//! S6 Throughput scenario: pure valid-frame latency benchmark.
//! All frames are valid — detector enabled but never triggered.

#include <filesystem>
#include <iostream>

#include <sodium.h>

#include "experiments/scenario_runner.hpp"

using namespace experiments;

namespace {

class S6Throughput final : public IScenario {
  public:
    std::string name() const override { return "S6_throughput"; }

    RunConfig config() const override {
        RunConfig cfg;
        cfg.warmup = 1000;
        cfg.baseline = 0;
        cfg.steps = {1000, 5000, 10000, 50000};
        cfg.runs = 5;
        cfg.warmupSeqStart = 1;
        return cfg;
    }

    std::string trialPhaseName() const override { return "measure"; }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& /*tc*/, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = cfg.warmup + idx + 1;
        return factory.buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (cfg.warmup + idx) * 100, cfg.cardId);
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }
    S6Throughput scenario;
    auto cfg = scenario.config();
    parseCliOverrides(argc, argv, cfg);
    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s6_throughput.csv", cfg.seed);
    metrics.writeHeader();
    runScenario(scenario, metrics, cfg);
    metrics.flush();
    std::cerr << "[S6] Done. Output: results/s6_throughput.csv\n";
    return 0;
}
