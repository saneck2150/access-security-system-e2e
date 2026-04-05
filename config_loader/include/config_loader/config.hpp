#pragma once

#include <cstdint>
#include <string>

#include <access_core/handle_frame.hpp>
#include <key_manager/key_manager.hpp>
#include <yaml-cpp/yaml.h>

//! Configuration loading from YAML files.
namespace config_loader {

//! Storage layer configuration.
struct StorageConfig {
    //! Path to SQLite database file.
    std::string sqlitePath = "data/access.db";
};

//! HTTP admin API configuration.
struct AdminConfig {
    //! Network interface to bind (e.g., "0.0.0.0" for all).
    std::string bindHost = "127.0.0.1";
    //! HTTP port number.
    uint16_t port = 8080;
    //! Token for admin authentication (X-Admin-Token header).
    std::string adminToken = "";
    //! Shared secret for hardware HMAC auth (64 hex chars = 32 bytes). Empty = disabled.
    std::string hwSharedSecretHex = "";
    //! Maximum file upload size in bytes.
    size_t maxUploadBytes = 20 * 1024 * 1024;
    //! Maximum events to keep in circular buffer.
    size_t maxEvents = 1024;
};

//! Key management configuration.
struct KeyManagementYaml {
    //! Active key version for encryption.
    uint32_t currentKeyVersion = 1;
    //! Allow decryption with previous key version.
    bool allowPreviousKeyVersion = true;
    //! Path to hex-encoded master key file.
    std::string masterKeyPath = "secrets/master_key.hex";
};

//! Security profile configuration for experiments.
//! Controls which hardening mechanisms are active.
//! Loaded from the "experiment:" YAML section.
struct ExperimentConfig {
    //! AEAD cipher: "xchacha20" = XChaCha20-Poly1305 (192-bit nonce); "chacha20" =
    //! ChaCha20-Poly1305 (96-bit nonce).
    std::string cipherMode = "xchacha20";
    //! Nonce strategy: "deterministic" = HMAC(K_nonce, context) (R1/R2);
    //! "random" = randombytes_buf (R0).
    std::string nonceMode = "deterministic";
    //! Key derivation: "hkdf" = per-reader HKDF key; "direct" = master key for all readers.
    std::string keyDerivationMode = "hkdf";
    //! AAD binding: "full" = header bytes as AAD; "none" = empty AAD (no context binding).
    std::string aadMode = "full";
    //! Card pepper: "versioned" = HKDF per key version; "static" = fixed version-1 pepper.
    std::string pepperMode = "versioned";
    //! Audit chain: true = HMAC-chained tamper-evident log; false = plain log.
    bool auditChainEnabled = true;
    //! R2 misuse detection: true = ProtocolAnomalyDetector active with quarantine.
    bool misuseDetectionEnabled = false;
    //! Sequence rollback threshold for anomaly detection.
    uint64_t rollbackThreshold = 100;
    //! Consecutive AEAD failures before reader quarantine.
    uint32_t tagFailStreakLimit = 5;
};

//! Complete application configuration.
struct Config {
    //! Frame handler settings (anti-replay, timing, etc.).
    access_core::FrameHandlerConfig frameHandler{};
    //! Storage layer settings.
    StorageConfig storage{};
    //! Admin API settings.
    AdminConfig admin{};
    //! Key management settings.
    KeyManagementYaml keyManagement{};
    //! Experiment/security profile settings.
    ExperimentConfig experiment{};
};

//! Loads configuration from a YAML file.
//! @param [in] path Path to the YAML configuration file.
//! @return Parsed configuration struct.
//! @throws std::runtime_error If file cannot be loaded or validation fails.
Config loadFromYaml(const std::string& path);

}  // namespace config_loader
