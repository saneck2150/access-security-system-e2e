#include <gtest/gtest.h>
#include <protocol_lib/replay_window.hpp>

using protocol::replay::ReplayWindow;

// Test basic accept/reject functionality
TEST(ReplayWindowTest, BasicAcceptReject) {
    ReplayWindow rw(4);

    EXPECT_TRUE(rw.accept(1));
    EXPECT_TRUE(rw.accept(2));
    EXPECT_TRUE(rw.accept(3));

    // Replay should be rejected
    EXPECT_FALSE(rw.accept(1));
    EXPECT_FALSE(rw.accept(2));
}

// Test window eviction still tracks maxSeen
TEST(ReplayWindowTest, EvictionStillTracksMax) {
    ReplayWindow rw(4);

    // Accept 1,2,3,4 - window full
    EXPECT_TRUE(rw.accept(1));
    EXPECT_TRUE(rw.accept(2));
    EXPECT_TRUE(rw.accept(3));
    EXPECT_TRUE(rw.accept(4));

    // Accept 5 - evicts 1 from _seen
    EXPECT_TRUE(rw.accept(5));

    // 1 is no longer in _seen, but it's "too old" (maxSeen=5, window=4)
    // seq 1 <= (5 - 4) = 1, so it's too old
    EXPECT_FALSE(rw.accept(1));
}

// Test that old sequence numbers outside window are rejected
TEST(ReplayWindowTest, OldSeqRejectedAfterWindowSlides) {
    ReplayWindow rw(256);

    // Accept seq 1..257
    for (uint64_t i = 1; i <= 257; ++i) {
        EXPECT_TRUE(rw.accept(i)) << "seq " << i << " should be accepted";
    }

    EXPECT_FALSE(rw.accept(1)) << "seq 1 should be rejected as too old";

    // seq 2 is also too old (2 <= 1 is false, so 2 > 1, not too old)
    // Actually: 2 <= (257 - 256) = 1 is false, so seq=2 is NOT too old
    // But seq=2 was already seen and is still in _seen
    EXPECT_FALSE(rw.accept(2)) << "seq 2 should be rejected (still in seen set)";
}

// Test edge case: very old sequence after many new ones
TEST(ReplayWindowTest, VeryOldSeqRejected) {
    ReplayWindow rw(10);

    // Accept 1..20
    for (uint64_t i = 1; i <= 20; ++i) {
        EXPECT_TRUE(rw.accept(i));
    }

    // maxSeen = 20, window = 10
    // seq 5 <= (20 - 10) = 10, so seq=5 is "too old"
    EXPECT_FALSE(rw.accept(5));

    // seq 10 <= 10, so seq=10 is also "too old"
    EXPECT_FALSE(rw.accept(10));

    // seq 11 > 10, so seq=11 is NOT too old, but was already seen
    EXPECT_FALSE(rw.accept(11));
}

// Test that new high sequence numbers are accepted
TEST(ReplayWindowTest, NewHighSeqAccepted) {
    ReplayWindow rw(10);

    EXPECT_TRUE(rw.accept(100));
    EXPECT_TRUE(rw.accept(200));
    EXPECT_TRUE(rw.accept(300));

    // Old ones are rejected
    EXPECT_FALSE(rw.accept(100));
    EXPECT_FALSE(rw.accept(1));  // way too old
}

// Test out-of-order within window is accepted
TEST(ReplayWindowTest, OutOfOrderWithinWindow) {
    ReplayWindow rw(10);

    EXPECT_TRUE(rw.accept(5));
    EXPECT_TRUE(rw.accept(3));  // out of order but within window
    EXPECT_TRUE(rw.accept(7));
    EXPECT_TRUE(rw.accept(1));  // still within window (maxSeen=7, 7-10 < 0)
}

// Test contains() also respects isTooOld
TEST(ReplayWindowTest, ContainsRespectsIsTooOld) {
    ReplayWindow rw(4);

    for (uint64_t i = 1; i <= 10; ++i) {
        rw.remember(i);
    }

    // maxSeen = 10, window = 4
    // seq 5 <= (10 - 4) = 6, so seq=5 is "too old"
    EXPECT_TRUE(rw.contains(5));
    EXPECT_TRUE(rw.contains(6));

    // seq 7 > 6, not too old, still in window
    EXPECT_TRUE(rw.contains(7));  // in _seen

    // seq 100 is not seen and not too old
    EXPECT_FALSE(rw.contains(100));
}
