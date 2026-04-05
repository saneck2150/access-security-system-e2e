#pragma once

//! @file frame_decryptor.hpp
//! AEAD decryption and timestamp validation for encrypted frames.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

namespace access_core {

//! Configuration for FrameDecryptor.
struct DecryptorConfig {
    uint64_t maxSkewMs = 0;        //!< Max allowed timestamp skew in ms (0 = disabled).
    std::string aadMode = "full";  //!< "full" = header as AAD; "none" = empty AAD.
};

//! Result of frame decryption attempt.
struct DecryptResult {
    bool success = false;            //!< True if decryption succeeded.
    std::string error;               //!< Error code if failed.
    std::vector<uint8_t> plaintext;  //!< Decrypted data (if successful).
};

//! Decrypts frames using AEAD and validates timestamps.
class FrameDecryptor {
  public:
    //! Constructs a decryptor with given AEAD instance.
    //! @param [in] aead   AEAD cipher for decryption (must outlive decryptor).
    //! @param [in] config Decryptor configuration.
    FrameDecryptor(crypto_lib::aead::SecureAead& aead, DecryptorConfig config = {});

    //! Decrypts a frame and validates timestamp.
    //! @param [in] frame Parsed frame to decrypt.
    //! @return DecryptResult with plaintext or error.
    DecryptResult decrypt(const protocol::frame::Frame& frame);

  private:
    crypto_lib::aead::SecureAead& _aead;
    DecryptorConfig _config;

    //! Performs AEAD decryption with header as AAD.
    std::vector<uint8_t> decryptFrame(const protocol::frame::Frame& frame);

    //! Validates frame timestamp against current time.
    //! @return Error string if invalid, nullopt if ok.
    std::optional<std::string> checkTimestamp(uint64_t frameTimestamp) const;

    //! Returns current Unix time in milliseconds.
    uint64_t nowUnixMs() const;
};

}  // namespace access_core
