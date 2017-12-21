#include <memory>

#include "gtest/gtest.h"

#include "common/DynamicBuffer.h"
#include "common/StaticByteBuffer.h"

namespace crypto {

TEST(StaticByteBufferTest, defaultConstruct) {
    StaticByteBuffer<10> sbb;
    EXPECT_TRUE(sbb.empty());
    EXPECT_FALSE(sbb.full());
    EXPECT_EQ(0U, sbb.size());
    EXPECT_EQ(10U, sbb.capacity());

    const StaticByteBuffer<5> csbb;
    EXPECT_TRUE(csbb.empty());
    EXPECT_FALSE(csbb.full());
    EXPECT_EQ(0U, csbb.size());
    EXPECT_EQ(5U, csbb.capacity());
}

TEST(StaticByteBufferTest, emptyBuffer) {
    StaticByteBuffer<9> sbb(0);
    EXPECT_TRUE(sbb.empty());
    EXPECT_FALSE(sbb.full());
    EXPECT_EQ(0U, sbb.size());
    EXPECT_EQ(9U, sbb.capacity());
}

TEST(StaticByteBufferTest, fullBuffer) {
    StaticByteBuffer<3> sbb(3);
    EXPECT_FALSE(sbb.empty());
    EXPECT_TRUE(sbb.full());
    EXPECT_EQ(3U, sbb.size());
    EXPECT_EQ(3U, sbb.capacity());
}

} // namespace crypto

