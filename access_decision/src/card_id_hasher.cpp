#include <crypto_lib/crypto_utils.hpp>

#include "access_decision/card_id_hasher.hpp"

#include <stdexcept>

namespace access_decision {

static std::string to_hex(const uint8_t* data, size_t n) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[2 * i + 0] = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[(data[i] >> 0) & 0xF];
    }
    return out;
}

CardIdHasher::CardIdHasher(std::array<uint8_t, 32> pepper_key) : _pepper(pepper_key) {}

std::string CardIdHasher::hmac_hex(std::string_view card_id) const {
    if (card_id.empty())
        throw std::runtime_error("card_id empty");
    unsigned char out[32]{};
    const auto key_span = std::span<const uint8_t>(_pepper.data(), _pepper.size());
    const auto data_span =
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(card_id.data()), card_id.size());
    crypto_lib::utils::hmac_sha256(key_span, data_span, out);
    return to_hex(reinterpret_cast<const uint8_t*>(out), 32);
}

}  // namespace access_decision
