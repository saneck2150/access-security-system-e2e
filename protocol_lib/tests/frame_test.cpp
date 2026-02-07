#include "protocol_lib/frame.hpp"

#include <gtest/gtest.h>

TEST(Frame, Roundtrip) {
    protocol::frame::Frame f;
    f.header.reader_id = 1;
    f.header.door_id = 2;
    f.header.ts_unix_ms = 1234;
    f.header.seq = 42;
    f.header.nonce.fill(0xAB);

    f.ct = {1, 2, 3, 4, 5};
    f.tag.v.fill(0xCD);

    const auto bytes = protocol::frame::serialize(f);
    const auto g = protocol::frame::parse(bytes);

    EXPECT_EQ(g.header.reader_id, f.header.reader_id);
    EXPECT_EQ(g.header.door_id, f.header.door_id);
    EXPECT_EQ(g.header.ts_unix_ms, f.header.ts_unix_ms);
    EXPECT_EQ(g.header.seq, f.header.seq);
    EXPECT_EQ(g.header.nonce, f.header.nonce);
    EXPECT_EQ(g.ct, f.ct);
    EXPECT_EQ(g.tag.v, f.tag.v);
}

TEST(Frame, TruncatedFails) {
    protocol::frame::Frame f;
    f.header.nonce.fill(0);
    const auto bytes = protocol::frame::serialize(f);

    ASSERT_GT(bytes.size(), 10u);
    const auto cut = std::span<const uint8_t>(bytes.data(), bytes.size() - 10);
    EXPECT_THROW((void)protocol::frame::parse(cut), std::runtime_error);
}
