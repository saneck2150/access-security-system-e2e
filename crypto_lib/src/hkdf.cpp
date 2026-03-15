#include "crypto_lib/hkdf.hpp"

#include <algorithm>
#include <stdexcept>

#include "crypto_lib/crypto_utils.hpp"

namespace crypto_lib::hkdf {

using crypto_lib::utils::hmac_sha256;

Hkdf::Hkdf(std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::string_view info,
    size_t outputLen)
    : _ikm(ikm), _salt(salt), _info(info), _outputLen(outputLen) {
    _okm.reserve(outputLen);
    _prevBlock.reserve(_hashLen);
    extract();
}

void Hkdf::extract() {
    if (_salt.empty()) {
        std::array<uint8_t, crypto_auth_hmacsha256_BYTES> zeros{};
        hmac_sha256(zeros, _ikm, _prk.data());
    } else {
        hmac_sha256(_salt, _ikm, _prk.data());
    }
}

size_t Hkdf::computeBlockCount() const {
    return (_outputLen + _hashLen - 1) / _hashLen;
}

void Hkdf::initHmacState(crypto_auth_hmacsha256_state& state) const {
    crypto_auth_hmacsha256_init(&state, _prk.data(), _prk.size());
}

void Hkdf::updateWithPrevBlock(crypto_auth_hmacsha256_state& state) const {
    if (!_prevBlock.empty()) {
        crypto_auth_hmacsha256_update(&state, _prevBlock.data(), _prevBlock.size());
    }
}

void Hkdf::updateWithInfo(crypto_auth_hmacsha256_state& state) const {
    if (!_info.empty()) {
        crypto_auth_hmacsha256_update(
            &state, reinterpret_cast<const unsigned char*>(_info.data()), _info.size());
    }
}

void Hkdf::updateWithBlockIndex(crypto_auth_hmacsha256_state& state, size_t blockIndex) const {
    const unsigned char counter = static_cast<unsigned char>(blockIndex);
    crypto_auth_hmacsha256_update(&state, &counter, 1);
}

void Hkdf::finalizeAndAppend(crypto_auth_hmacsha256_state& state) {
    _prevBlock.resize(_hashLen);
    crypto_auth_hmacsha256_final(&state, _prevBlock.data());

    const size_t toCopy = std::min(_hashLen, _outputLen - _okm.size());
    _okm.insert(_okm.end(), _prevBlock.begin(), _prevBlock.begin() + toCopy);
}

void Hkdf::expandBlock(size_t blockIndex) {
    crypto_auth_hmacsha256_state state;
    initHmacState(state);
    updateWithPrevBlock(state);
    updateWithInfo(state);
    updateWithBlockIndex(state, blockIndex);
    finalizeAndAppend(state);
}

std::vector<uint8_t> Hkdf::derive() {
    const size_t blockCount = computeBlockCount();
    if (blockCount > 255) {
        throw std::invalid_argument("Hkdf: outputLen too large");
    }

    for (size_t i = 1; i <= blockCount; ++i) {
        expandBlock(i);
    }
    return _okm;
}

}  // namespace crypto_lib::hkdf
