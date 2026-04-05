#include "access_decision/card_id_hasher.hpp"

#include <stdexcept>

#include <crypto_lib/crypto_utils.hpp>

namespace access_decision {

CardIdHasher::CardIdHasher(std::array<uint8_t, kHmacOutputSize> pepperKey) : _pepper(pepperKey) {}

std::string CardIdHasher::toHex(const uint8_t* data, size_t length) const {
    std::string result;
    result.resize(length * 2);
    for (size_t i = 0; i < length; ++i) {
        result[2 * i + 0] = kHexChars[(data[i] >> 4) & 0xF];
        result[2 * i + 1] = kHexChars[(data[i] >> 0) & 0xF];
    }
    return result;
}

std::string CardIdHasher::hmacHex(std::string_view cardId) const {
    if (cardId.empty()) {
        throw std::runtime_error("cardId empty");
    }
    unsigned char hmacOutput[kHmacOutputSize]{};
    const auto keySpan = std::span<const uint8_t>(_pepper.data(), _pepper.size());
    const auto dataSpan =
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(cardId.data()), cardId.size());
    crypto_lib::utils::hmac_sha256(keySpan, dataSpan, hmacOutput);
    return toHex(hmacOutput, kHmacOutputSize);
}

}  // namespace access_decision
