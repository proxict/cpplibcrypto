#include <memory>

#include "gtest/gtest.h"

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
    StaticByteBuffer<11> bb{0x02, 0x03};
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

TEST(StaticBufferTest, eraseElement) {
    StaticByteBuffer<5> bb{0x01, 0x02, 0x03, 0x04, 0x05};

    const auto next = bb.erase(2);
    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(StaticByteBuffer<4>({0x01, 0x02, 0x04, 0x05}), bb);
    EXPECT_EQ(4U, *next);
}

TEST(StaticBufferTest, eraseElementsCount) {
    StaticByteBuffer<8> bb{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(8U, bb.size());

    auto next = bb.erase(1, 3);
    EXPECT_EQ(5U, bb.size());
    EXPECT_EQ(StaticByteBuffer<5>({0x01, 0x05, 0x06, 0x07, 0x08}), bb);
    EXPECT_EQ(5U, *next);

    next = bb.erase(0, 1);
    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(StaticByteBuffer<4>({0x05, 0x06, 0x07, 0x08}), bb);
    EXPECT_EQ(5U, *next);

    next = bb.erase(2, 2);
    EXPECT_EQ(2U, bb.size());
    EXPECT_EQ(StaticByteBuffer<2>({0x05, 0x06}), bb);
    EXPECT_TRUE(next == bb.end());
    
    next = bb.erase(0, 2);
    EXPECT_EQ(0U, bb.size());
    EXPECT_TRUE(next == bb.end());
}

TEST(StaticBufferTest, eraseElementRange) {
    StaticByteBuffer<8> bb{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(8U, bb.size());

    auto next = bb.erase(bb.begin() + 1, bb.begin() + 4);
    EXPECT_EQ(5U, bb.size());
    EXPECT_EQ(StaticByteBuffer<5>({0x01, 0x05, 0x06, 0x07, 0x08}), bb);
    EXPECT_EQ(5U, *next);

    next = bb.erase(bb.begin(), bb.begin() + 1);
    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(StaticByteBuffer<4>({0x05, 0x06, 0x07, 0x08}), bb);
    EXPECT_EQ(5U, *next);

    next = bb.erase(bb.end() - 1, bb.end());
    EXPECT_EQ(3U, bb.size());
    EXPECT_EQ(StaticByteBuffer<3>({0x05, 0x06, 0x07}), bb);
    EXPECT_TRUE(next == bb.end());

    next = bb.erase(bb.begin(), bb.end());
    EXPECT_EQ(0U, bb.size());
    EXPECT_TRUE(next == bb.end());
}

TEST(StaticBufferTest, replaceElements) {
    StaticByteBuffer<7> db{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    StaticByteBuffer<6> sb{ 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const auto replaced = db.replace(db.begin() + 1, db.begin() + 4, sb.begin() + 2);

    EXPECT_EQ(StaticByteBuffer<7>({0x00, 0x0c, 0x0d, 0x0e, 0x04, 0x05, 0x06}), db);
    EXPECT_EQ(0x0c, *replaced);
}

TEST(StaticBufferTest, resize) {
    StaticByteBuffer<15> bb(10);
    EXPECT_EQ(10U, bb.size());
    EXPECT_EQ(0U, bb[9]);

    bb[0] = 3;
    bb.resize(1);
    EXPECT_EQ(1U, bb.size());
    EXPECT_EQ(3U, bb[0]);

    bb.resize(15);
    EXPECT_EQ(15U, bb.size());
    EXPECT_EQ(3U, bb[0]);
    EXPECT_EQ(0U, bb[10]);
}

} // namespace crypto

