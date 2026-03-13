#include <gtest/gtest.h>
#include "core/model/PredictionResult.h"
#include "core/model/AttackType.h"

using nids::core::PredictionResult;
using nids::core::AttackType;
using nids::core::kAttackTypeCount;

TEST(PredictionResult, defaultConstruction_isUnknown) {
    PredictionResult result;
    EXPECT_EQ(result.classification, AttackType::Unknown);
    EXPECT_FLOAT_EQ(result.confidence, 0.0f);
    EXPECT_TRUE(result.isUnknown());
}

TEST(PredictionResult, isAttack_trueForAttackTypes) {
    PredictionResult result;
    result.classification = AttackType::DdosIcmp;
    result.confidence = 0.9f;
    EXPECT_TRUE(result.isAttack());
}

TEST(PredictionResult, isAttack_falseForBenign) {
    PredictionResult result;
    result.classification = AttackType::Benign;
    result.confidence = 0.99f;
    EXPECT_FALSE(result.isAttack());
}

TEST(PredictionResult, isAttack_falseForUnknown) {
    PredictionResult result;
    result.classification = AttackType::Unknown;
    EXPECT_FALSE(result.isAttack());
}

TEST(PredictionResult, isHighConfidence_trueAboveThreshold) {
    PredictionResult result;
    result.classification = AttackType::SshBruteForce;
    result.confidence = 0.85f;
    EXPECT_TRUE(result.isHighConfidence(0.7f));
}

TEST(PredictionResult, isHighConfidence_falseBelowThreshold) {
    PredictionResult result;
    result.classification = AttackType::SshBruteForce;
    result.confidence = 0.5f;
    EXPECT_FALSE(result.isHighConfidence(0.7f));
}

TEST(PredictionResult, probabilitiesArray_defaultZero) {
    PredictionResult result;
    for (std::size_t i = 0; i < kAttackTypeCount; ++i) {
        EXPECT_FLOAT_EQ(result.probabilities[i], 0.0f);
    }
}
