//! @file s3_rng_fault.cpp
//! S3 RNG Fault scenario (two sub-scenarios):
//! S3a — FixedNonceGenerator: same nonce for all frames (broken RNG).
//!   R0/R1: pass (no nonce verification). R2: quarantine nonce_mismatch.
//! S3b — SeededNonceGenerator on deterministic-mode engine (wrong nonce).
//!   R0/R1: pass. R2: quarantine nonce_mismatch.

#include <filesystem>
#include <iostream>
#include <memory>

#include <sodium.h>

#include <crypto_lib/nonce_generator.hpp>
#include "experiments/scenario_common.hpp"
#include "experiments/scenario_runner.hpp"
#include "experiments/seeded_nonce_generator.hpp"

using namespace experiments;

namespace {

//! Always returns the same nonce (simulates broken RNG).
class FixedNonceGenerator final : public crypto_lib::nonce::INonceGenerator {
  public:
    explicit FixedNonceGenerator(size_t nonceLen) : _nonceLen(nonceLen) {
        _nonce.fill(0);
        for (size_t i = 0; i < _nonceLen; ++i) {
            _nonce[i] = 0xAA;
        }
    }

    std::array<uint8_t, 24> generate(
        std::span<const uint8_t> /*context*/, uint64_t /*seq*/) override {
        return _nonce;
    }

  private:
    std::array<uint8_t, 24> _nonce{};
    size_t _nonceLen;
};

//! Base class for S3 sub-scenarios. Holds a separate attack factory.
class S3Base : public IScenario {
  protected:
    std::unique_ptr<FrameFactory> _attackFactory;

  public:
    RunConfig config() const override { return {}; }

    std::vector<uint8_t> buildTrialFrame(FrameFactory& /*factory*/, const RunConfig& cfg,
        const TrialContext& tc, uint32_t idx, uint32_t /*stepN*/) override {
        uint64_t seq = tc.trialSeqStart + idx;
        return _attackFactory->buildFrame(cfg.readerId, cfg.doorId, seq, cfg.keyVersion,
            cfg.baseTs + (tc.totalFramesBefore + idx) * 100, cfg.cardId);
    }
};

//! S3a: broken RNG — same nonce every frame.
class S3aFixedNonce final : public S3Base {
  public:
    std::string name() const override { return "S3a_fixed_nonce"; }

    void setup(ExperimentContext& /*ctx*/, FrameFactory& /*factory*/,
        const key_manager::KeyManager& km,
        const ProfileConfig& profile) override {
        auto cm = (profile.cipherMode == "chacha20")
                      ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                      : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
        _attackFactory = std::make_unique<FrameFactory>(km, profile,
            std::make_unique<FixedNonceGenerator>(crypto_lib::nonce::nonceLenFor(cm)));
    }
};

//! S3b: wrong nonce (seeded random on deterministic-mode engine).
class S3bWrongNonce final : public S3Base {
  public:
    std::string name() const override { return "S3b_wrong_nonce"; }

    void setup(ExperimentContext& /*ctx*/, FrameFactory& /*factory*/,
        const key_manager::KeyManager& km,
        const ProfileConfig& profile) override {
        auto cm = (profile.cipherMode == "chacha20")
                      ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                      : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
        _attackFactory = std::make_unique<FrameFactory>(km, profile,
            std::make_unique<SeededNonceGenerator>(seedToArray(42 + 1), cm));
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    S3aFixedNonce s3a;
    S3bWrongNonce s3b;
    auto cfg = s3a.config();
    parseCliOverrides(argc, argv, cfg);

    std::filesystem::create_directories("results");
    MetricsCollector metrics("results/s3_rng_fault.csv", cfg.seed);
    metrics.writeHeader();

    runScenario(s3a, metrics, cfg);
    runScenario(s3b, metrics, cfg);

    metrics.flush();
    std::cerr << "[S3] Done. Output: results/s3_rng_fault.csv\n";
    return 0;
}
