#include <access_core/protocol_anomaly_detector.hpp>
#include <gtest/gtest.h>
#include <sodium.h>

using access_core::AnomalyType;
using access_core::DetectorConfig;
using access_core::ProtocolAnomalyDetector;

static constexpr uint64_t kTs = 1000;

class AnomalyDetectorTest : public ::testing::Test {
  protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }

    ProtocolAnomalyDetector makeDetector(
        uint64_t rollback = 100, uint32_t tagLimit = 5) {
        return ProtocolAnomalyDetector(
            DetectorConfig{.enabled = true,
                .rollbackThreshold = rollback,
                .tagFailStreakLimit = tagLimit});
    }
};

// --- Quarantine lifecycle ---

TEST_F(AnomalyDetectorTest, NotQuarantinedByDefault) {
    auto det = makeDetector();
    EXPECT_FALSE(det.isQuarantined(1));
    EXPECT_FALSE(det.quarantineInfo(1).has_value());
}

TEST_F(AnomalyDetectorTest, UnquarantineReturnsFalseIfNotQuarantined) {
    auto det = makeDetector();
    EXPECT_FALSE(det.unquarantine(1));
}

// --- seq_reuse ---

TEST_F(AnomalyDetectorTest, ReplayQuarantinesImmediately) {
    auto det = makeDetector();
    auto type = det.reportReplay(1, 42, kTs);
    EXPECT_EQ(type, AnomalyType::seq_reuse);
    EXPECT_TRUE(det.isQuarantined(1));

    auto info = det.quarantineInfo(1);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->reason, AnomalyType::seq_reuse);
    EXPECT_EQ(info->ts_unix_ms, kTs);
}

TEST_F(AnomalyDetectorTest, ReplayDoesNotAffectOtherReaders) {
    auto det = makeDetector();
    det.reportReplay(1, 42, kTs);
    EXPECT_FALSE(det.isQuarantined(2));
}

// --- seq_rollback ---

TEST_F(AnomalyDetectorTest, NormalSeqProgressNoRollback) {
    auto det = makeDetector(100);
    // Advance seq
    det.reportSuccess(1, 500);
    // Seq 450 is within threshold (500 - 450 = 50 < 100)
    auto result = det.reportSeq(1, 450, kTs);
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(det.isQuarantined(1));
}

TEST_F(AnomalyDetectorTest, RollbackQuarantines) {
    auto det = makeDetector(100);
    det.reportSuccess(1, 500);
    // Seq 300 is far below maxSeen (500 - 300 = 200 > 100)
    auto result = det.reportSeq(1, 300, kTs);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, AnomalyType::seq_rollback);
    EXPECT_TRUE(det.isQuarantined(1));
}

TEST_F(AnomalyDetectorTest, RollbackEdgeCaseExact) {
    auto det = makeDetector(100);
    det.reportSuccess(1, 200);
    // seq=100: 100 + 100 = 200, NOT < 200 → no rollback
    auto result = det.reportSeq(1, 100, kTs);
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(det.isQuarantined(1));
}

TEST_F(AnomalyDetectorTest, RollbackEdgeCaseOneBelow) {
    auto det = makeDetector(100);
    det.reportSuccess(1, 200);
    // seq=99: 99 + 100 = 199 < 200 → rollback
    auto result = det.reportSeq(1, 99, kTs);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, AnomalyType::seq_rollback);
}

// --- nonce_mismatch ---

TEST_F(AnomalyDetectorTest, NonceMismatchQuarantines) {
    auto det = makeDetector();
    auto type = det.reportNonceMismatch(1, kTs);
    EXPECT_EQ(type, AnomalyType::nonce_mismatch);
    EXPECT_TRUE(det.isQuarantined(1));
}

// --- tag_fail_streak ---

TEST_F(AnomalyDetectorTest, TagFailsBelowLimitNoQuarantine) {
    auto det = makeDetector(100, 5);
    for (uint32_t i = 0; i < 4; ++i) {
        auto result = det.reportTagFailure(1, kTs);
        EXPECT_FALSE(result.has_value()) << "i=" << i;
    }
    EXPECT_FALSE(det.isQuarantined(1));
}

TEST_F(AnomalyDetectorTest, TagFailsAtLimitQuarantines) {
    auto det = makeDetector(100, 5);
    for (uint32_t i = 0; i < 4; ++i) {
        det.reportTagFailure(1, kTs);
    }
    auto result = det.reportTagFailure(1, kTs);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, AnomalyType::tag_fail_streak);
    EXPECT_TRUE(det.isQuarantined(1));
}

TEST_F(AnomalyDetectorTest, SuccessResetsTagFailStreak) {
    auto det = makeDetector(100, 5);
    // 4 failures
    for (uint32_t i = 0; i < 4; ++i) {
        det.reportTagFailure(1, kTs);
    }
    // Success resets streak
    det.reportSuccess(1, 10);
    // 4 more failures → still below limit
    for (uint32_t i = 0; i < 4; ++i) {
        auto result = det.reportTagFailure(1, kTs);
        EXPECT_FALSE(result.has_value());
    }
    EXPECT_FALSE(det.isQuarantined(1));
}

// --- unquarantine ---

TEST_F(AnomalyDetectorTest, UnquarantineWorks) {
    auto det = makeDetector();
    det.reportReplay(1, 42, kTs);
    EXPECT_TRUE(det.isQuarantined(1));

    EXPECT_TRUE(det.unquarantine(1));
    EXPECT_FALSE(det.isQuarantined(1));
    EXPECT_FALSE(det.quarantineInfo(1).has_value());
}

TEST_F(AnomalyDetectorTest, UnquarantineResetsTagStreak) {
    auto det = makeDetector(100, 3);
    // 2 fails, then quarantine via replay
    det.reportTagFailure(1, kTs);
    det.reportTagFailure(1, kTs);
    det.reportReplay(1, 10, kTs);

    det.unquarantine(1);
    // After unquarantine, streak is reset → need 3 fresh failures
    for (uint32_t i = 0; i < 2; ++i) {
        auto result = det.reportTagFailure(1, kTs);
        EXPECT_FALSE(result.has_value());
    }
    EXPECT_FALSE(det.isQuarantined(1));
}

// --- nonceEqual ---

TEST_F(AnomalyDetectorTest, NonceEqualIdentical) {
    std::array<uint8_t, 24> a{};
    randombytes_buf(a.data(), a.size());
    EXPECT_TRUE(ProtocolAnomalyDetector::nonceEqual(a, a, 24));
    EXPECT_TRUE(ProtocolAnomalyDetector::nonceEqual(a, a, 12));
}

TEST_F(AnomalyDetectorTest, NonceEqualDifferent) {
    std::array<uint8_t, 24> a{}, b{};
    randombytes_buf(a.data(), a.size());
    randombytes_buf(b.data(), b.size());
    EXPECT_FALSE(ProtocolAnomalyDetector::nonceEqual(a, b, 24));
}

TEST_F(AnomalyDetectorTest, NonceEqualPartialMatch12) {
    std::array<uint8_t, 24> a{}, b{};
    randombytes_buf(a.data(), 12);
    b = a;
    // Differ only in bytes 12-23
    b[12] ^= 0xFF;
    EXPECT_TRUE(ProtocolAnomalyDetector::nonceEqual(a, b, 12));
    EXPECT_FALSE(ProtocolAnomalyDetector::nonceEqual(a, b, 24));
}

// --- anomalyTypeToString ---

TEST_F(AnomalyDetectorTest, TypeToStringCoversAll) {
    EXPECT_STREQ(access_core::anomalyTypeToString(AnomalyType::seq_reuse), "seq_reuse");
    EXPECT_STREQ(access_core::anomalyTypeToString(AnomalyType::seq_rollback), "seq_rollback");
    EXPECT_STREQ(access_core::anomalyTypeToString(AnomalyType::nonce_mismatch), "nonce_mismatch");
    EXPECT_STREQ(access_core::anomalyTypeToString(AnomalyType::tag_fail_streak), "tag_fail_streak");
}
