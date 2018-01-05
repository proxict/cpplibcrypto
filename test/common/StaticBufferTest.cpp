#include <memory>

#include "gtest/gtest.h"

#include "common/DynamicBuffer.h"
#include "common/StaticBuffer.h"

namespace crypto {

template <Size TSize>
using StaticByteBuffer = StaticBuffer<Byte, TSize>;

TEST(StaticBufferTest, defaultConstruct) {
    StaticBuffer<Byte, 10> sbb;
    EXPECT_TRUE(sbb.empty());
    EXPECT_FALSE(sbb.full());
    EXPECT_EQ(0U, sbb.size());
    EXPECT_EQ(10U, sbb.capacity());

    const StaticBuffer<Byte, 5> csbb;
    EXPECT_TRUE(csbb.empty());
    EXPECT_FALSE(csbb.full());
    EXPECT_EQ(0U, csbb.size());
    EXPECT_EQ(5U, csbb.capacity());
}

TEST(StaticBufferTest, emptyBuffer) {
    StaticBuffer<Byte, 9> sbb(0);
    EXPECT_TRUE(sbb.empty());
    EXPECT_FALSE(sbb.full());
    EXPECT_EQ(0U, sbb.size());
    EXPECT_EQ(9U, sbb.capacity());
}

TEST(StaticBufferTest, fullBuffer) {
    StaticBuffer<Byte, 3> sbb(3);
    EXPECT_FALSE(sbb.empty());
    EXPECT_TRUE(sbb.full());
    EXPECT_EQ(3U, sbb.size());
    EXPECT_EQ(3U, sbb.capacity());
}

TEST(StaticBufferTest, insertElement) {
    ByteBuffer bb{0x02, 0x03};
    Byte arr[] = {0x00, 0x01};
    bb.insert(bb.begin(), arr, arr + 2);
    EXPECT_EQ(ByteBuffer({0x00, 0x01, 0x02, 0x03}), bb);

    Byte arr2[] = {0x04, 0x05};
    bb.insert(bb.end(), arr2, arr2 + 2);
    EXPECT_EQ(ByteBuffer({0x00, 0x01, 0x02, 0x03, 0x04, 0x05}), bb);

    Byte arr3[] = {0x06, 0x07, 0x08};
    bb.insert(bb.begin() + 3, arr3, arr3 + 3);
    EXPECT_EQ(ByteBuffer({0x00, 0x01, 0x02, 0x06, 0x07, 0x08, 0x03, 0x04, 0x05}), bb);

    Byte arr4[] = {0x0a, 0x0b};
    bb.insert(bb.begin() + 1, arr4, arr4 + 2);
    EXPECT_EQ(ByteBuffer({0x00, 0x0a, 0x0b, 0x01, 0x02, 0x06, 0x07, 0x08, 0x03, 0x04, 0x05}), bb);
}

TEST(StaticBufferTest, insertElements) {
    StaticByteBuffer<15> bb{0x02, 0x03};
    Byte arr[] = {0x00, 0x01};
    bb.insert(bb.begin(), arr, arr + 2);
    EXPECT_EQ(StaticByteBuffer<4>({0x00, 0x01, 0x02, 0x03}), bb);

    Byte arr2[] = {0x04, 0x05};
    bb.insert(bb.end(), arr2, arr2 + 2);
    EXPECT_EQ(StaticByteBuffer<6>({0x00, 0x01, 0x02, 0x03, 0x04, 0x05}), bb);

    Byte arr3[] = {0x06, 0x07, 0x08};
    bb.insert(bb.begin() + 3, arr3, arr3 + 3);
    EXPECT_EQ(StaticByteBuffer<9>({0x00, 0x01, 0x02, 0x06, 0x07, 0x08, 0x03, 0x04, 0x05}), bb);

    Byte arr4[] = {0x0a, 0x0b};
    bb.insert(bb.begin() + 1, arr4, arr4 + 2);
    EXPECT_EQ(StaticByteBuffer<11>({0x00, 0x0a, 0x0b, 0x01, 0x02, 0x06, 0x07, 0x08, 0x03, 0x04, 0x05}), bb);
}

} // namespace crypto

