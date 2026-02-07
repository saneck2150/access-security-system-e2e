#pragma once

#include <cstdint>
#include <vector>

namespace protocol::utils {

void put_le32(uint32_t v, std::vector<uint8_t>& out);
void put_le64(uint64_t v, std::vector<uint8_t>& out);

uint32_t get_le32(const uint8_t* p);
uint64_t get_le64(const uint8_t* p);

}  // namespace protocol::utils