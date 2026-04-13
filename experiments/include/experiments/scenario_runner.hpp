#pragma once

//! @file scenario_runner.hpp
//! Common experiment runner: RunConfig, TrialContext, IScenario, runScenario().

#include <cstdint>
#include <string>
#include <vector>

#include <key_manager/key_manager.hpp>

#include "experiments/experiment_context.hpp"
#include "experiments/frame_factory.hpp"
#include "experiments/metrics_collector.hpp"

namespace experiments {

//! All experiment parameters in one struct.
//! Scenario's config() returns defaults; CLI overrides modify in-place.
struct RunConfig {
    uint64_t seed = 42;
    uint32_t readerId = 1;
    uint32_t doorId = 7;
    uint32_t keyVersion = 1;
    uint64_t baseTs = 1700000000000ULL;
    std::string cardId = "CARD1";
    uint32_t warmup = 200;
    uint32_t baseline = 200;
    std::vector<uint32_t> steps = {50, 100, 150, 200, 250, 300, 350, 400, 450, 500};
    uint32_t runs = 5;
    uint64_t warmupSeqStart = 10000;
    uint64_t baselineSeqStart = 20000;
    //! If non-empty, run in E2E mode: POST frames to this URL instead of in-process engine.
    std::string e2eUrl;
    //! If non-empty, run only this profile (e.g. "A1-R0"). Empty = all profiles.
    std::string profileFilter;
};

//! State computed by the runner and passed to buildTrialFrame().
struct TrialContext {
    uint64_t trialSeqStart;      //!< First seq for trial phase.
    uint64_t maxSeenSeq;         //!< Highest seq seen before trial.
    uint32_t totalFramesBefore;  //!< warmup + baseline (for timestamp offset).
};

//! Interface for experiment scenarios.
//! Scenarios implement only the unique logic; the runner handles the common loop.
class IScenario {
  public:
    virtual ~IScenario() = default;

    //! Scenario identifier (used in CSV and db path). E.g. "S1_replay".
    virtual std::string name() const = 0;

    //! Default run configuration. Scenarios override to customize seq offsets, etc.
    virtual RunConfig config() const = 0;

    //! Called after ExperimentContext + FrameFactory creation, before warmup.
    //! Reset per-iteration state here (e.g. S1 clears captured frame).
    virtual void setup(ExperimentContext& ctx, FrameFactory& factory,
        const key_manager::KeyManager& km,
        const ProfileConfig& profile) {}

    //! Called after each baseline frame is processed.
    //! @param [in] idx       Frame index within baseline.
    //! @param [in] total     Total baseline frame count.
    //! @param [in] frame     Serialized frame bytes.
    virtual void onBaselineFrame(uint32_t idx, uint32_t total,
        const std::vector<uint8_t>& frame) {}

    //! Build the i-th trial frame (attack or measurement).
    //! @param [in] factory   Standard FrameFactory (scenario may ignore and use its own).
    //! @param [in] cfg       Run configuration.
    //! @param [in] tc        Computed trial context (seq offsets, maxSeen).
    //! @param [in] idx       Frame index within trial.
    //! @param [in] stepN     Total trial frame count for this step.
    virtual std::vector<uint8_t> buildTrialFrame(
        FrameFactory& factory, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t stepN) = 0;

    //! Phase name for trial CSV column. Default "attack"; S6 returns "measure".
    virtual std::string trialPhaseName() const { return "attack"; }
};

//! Runs the full experiment loop for one scenario.
//! @param [in] scenario  Scenario implementation.
//! @param [in] metrics   CSV collector (already opened with header written).
//! @param [in] cfg       Run configuration (scenario defaults + CLI overrides).
void runScenario(IScenario& scenario, MetricsCollector& metrics, const RunConfig& cfg);

//! Overrides RunConfig fields from CLI arguments.
//! Supports: --seed=N, --warmup=N, --baseline=N, --runs=N.
void parseCliOverrides(int argc, char** argv, RunConfig& cfg);

}  // namespace experiments
