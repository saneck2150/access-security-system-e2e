#include "experiments/scenario_runner.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "experiments/scenario_common.hpp"

namespace experiments {

using Clock = std::chrono::steady_clock;

void runScenario(IScenario& scenario, MetricsCollector& metrics, const RunConfig& cfg) {
    const auto mk = makeMasterKey();
    const auto profiles = allProfiles();
    const auto scenarioName = scenario.name();
    const auto trialPhase = scenario.trialPhaseName();

    for (const auto& profile : profiles) {
        std::cerr << '[' << scenarioName << "] Profile: " << profile.label << '\n';

        key_manager::KeyManager km(mk,
            {.currentKeyVersion = cfg.keyVersion, .allowPreviousKeyVersion = true});

        for (const auto stepN : cfg.steps) {
            for (uint32_t run = 0; run < cfg.runs; ++run) {
                const std::string dbPath =
                    "/tmp/exp_" + scenarioName + "_" + profile.label + ".db";
                ExperimentContext ctx(profile, mk, dbPath,
                    cfg.readerId, cfg.doorId, cfg.keyVersion, {cfg.cardId});
                FrameFactory factory(km, profile,
                    makeNonceGen(profile, km, cfg.seed + run, cfg.readerId, cfg.keyVersion));

                scenario.setup(ctx, factory, km, profile);

                // Warmup (not recorded).
                for (uint32_t i = 0; i < cfg.warmup; ++i) {
                    auto frame = factory.buildFrame(cfg.readerId, cfg.doorId,
                        cfg.warmupSeqStart + i, cfg.keyVersion,
                        cfg.baseTs + i * 100, cfg.cardId);
                    ctx.processFrame(frame);
                }

                // Baseline (skipped if cfg.baseline == 0).
                for (uint32_t i = 0; i < cfg.baseline; ++i) {
                    uint64_t seq = cfg.baselineSeqStart + i;
                    auto frame = factory.buildFrame(cfg.readerId, cfg.doorId, seq,
                        cfg.keyVersion,
                        cfg.baseTs + (cfg.warmup + i) * 100, cfg.cardId);

                    auto t0 = Clock::now();
                    auto res = ctx.processFrame(frame);
                    auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now() - t0).count();

                    scenario.onBaselineFrame(i, cfg.baseline, frame);

                    metrics.append({profile.label, profile.cipherMode, profile.nonceMode,
                        profile.detectorEnabled, scenarioName, "baseline", stepN,
                        i, res.allow, res.reason, ctx.isQuarantined(cfg.readerId),
                        ctx.quarantineAnomalyType(cfg.readerId),
                        static_cast<uint64_t>(dt), run});
                }

                // Compute trial context.
                TrialContext tc{};
                if (cfg.baseline > 0) {
                    tc.trialSeqStart = cfg.baselineSeqStart + cfg.baseline;
                    tc.maxSeenSeq = cfg.baselineSeqStart + cfg.baseline - 1;
                } else {
                    tc.trialSeqStart = cfg.warmupSeqStart + cfg.warmup;
                    tc.maxSeenSeq = cfg.warmupSeqStart + cfg.warmup - 1;
                }
                tc.totalFramesBefore = cfg.warmup + cfg.baseline;

                // Trial (attack or measurement).
                for (uint32_t i = 0; i < stepN; ++i) {
                    auto frame = scenario.buildTrialFrame(factory, cfg, tc, i, stepN);

                    auto t0 = Clock::now();
                    auto res = ctx.processFrame(frame);
                    auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now() - t0).count();

                    metrics.append({profile.label, profile.cipherMode, profile.nonceMode,
                        profile.detectorEnabled, scenarioName, trialPhase, stepN,
                        i, res.allow, res.reason, ctx.isQuarantined(cfg.readerId),
                        ctx.quarantineAnomalyType(cfg.readerId),
                        static_cast<uint64_t>(dt), run});
                }

                std::filesystem::remove(dbPath);
            }
        }
    }
}

void parseCliOverrides(int argc, char** argv, RunConfig& cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto eq = arg.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = arg.substr(0, eq);
        std::string val = arg.substr(eq + 1);

        if (key == "--seed") {
            cfg.seed = std::stoull(val);
        } else if (key == "--warmup") {
            cfg.warmup = static_cast<uint32_t>(std::stoul(val));
        } else if (key == "--baseline") {
            cfg.baseline = static_cast<uint32_t>(std::stoul(val));
        } else if (key == "--runs") {
            cfg.runs = static_cast<uint32_t>(std::stoul(val));
        }
    }
}

}  // namespace experiments
