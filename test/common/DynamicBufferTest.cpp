#include <memory>

#include "gtest/gtest.h"

#include "common/DynamicBuffer.h"
#include "common/HexString.h"

namespace crypto {

TEST(DynamicBufferTest, ctor) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_EQ(5U, bb.size());

    EXPECT_EQ(0x01, bb[0]);
    EXPECT_EQ(0x02, bb[1]);
    EXPECT_EQ(0x03, bb[2]);
    EXPECT_EQ(0x04, bb[3]);
    EXPECT_EQ(0x05, bb[4]);
}

TEST(DynamicBufferTest, addingByte) {
    ByteBuffer bb;
    bb += 0xab;
    bb += 0xac;

    EXPECT_EQ(0xab, bb[0]);
    EXPECT_EQ(0xac, bb[1]);
}

TEST(DynamicBufferTest, chainingBuffers) {
    ByteBuffer bb1;
    bb1 += 0xab;
    bb1 += 0xcd;

    ByteBuffer bb2;
    bb2 += 0xef;
    bb2 += 0xff;

    ByteBuffer bb;
    bb += 0x00 + bb1 + bb2 + 0x0f;

    EXPECT_EQ(ByteBuffer({0x00, 0xab, 0xcd, 0xef, 0xff, 0x0f}), bb);
}

TEST(DynamicBufferTest, eraseElement) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05};
    bb.erase(2);

    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(ByteBuffer({0x01, 0x02, 0x04, 0x05}), bb);
}

TEST(DynamicBufferTest, eraseElementsCount) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(8U, bb.size());

    bb.erase(1, 3);
    EXPECT_EQ(5U, bb.size());
    EXPECT_EQ(ByteBuffer({0x01, 0x05, 0x06, 0x07, 0x08}), bb);

    bb.erase(0, 1);
    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(ByteBuffer({0x05, 0x06, 0x07, 0x08}), bb);

    bb.erase(2, 2);
    EXPECT_EQ(2U, bb.size());
    EXPECT_EQ(ByteBuffer({0x05, 0x06}), bb);
    
    bb.erase(0, 2);
    EXPECT_EQ(0U, bb.size());
}

TEST(DynamicBufferTest, eraseElementRange) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(8U, bb.size());

    bb.erase(bb.begin() + 1, bb.begin() + 4);
    EXPECT_EQ(5U, bb.size());
    EXPECT_EQ(ByteBuffer({0x01, 0x05, 0x06, 0x07, 0x08}), bb);

    bb.erase(bb.begin(), bb.begin() + 1);
    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(ByteBuffer({0x05, 0x06, 0x07, 0x08}), bb);

    bb.erase(bb.end() - 1, bb.end());
    EXPECT_EQ(3U, bb.size());
    EXPECT_EQ(ByteBuffer({0x05, 0x06, 0x07}), bb);

    bb.erase(bb.begin(), bb.end());
    EXPECT_EQ(0U, bb.size());
}

TEST(DynamicBufferTest, insertElement) {
    ByteBuffer bb{0x01, 0x02, 0x03};
    bb.insert(1U, 0x00);
    EXPECT_EQ(ByteBuffer({0x01, 0x00, 0x02, 0x03}), bb);
    bb.insert(3U, 0x08);
    EXPECT_EQ(ByteBuffer({0x01, 0x00, 0x02, 0x08, 0x03}), bb);
    bb.insert(0U, 0x06);
    EXPECT_EQ(ByteBuffer({0x06, 0x01, 0x00, 0x02, 0x08, 0x03}), bb);
    bb.insert(2U, 0x07);
    EXPECT_EQ(ByteBuffer({0x06, 0x01, 0x07, 0x00, 0x02, 0x08, 0x03}), bb);
}

TEST(DynamicBufferTest, storeReference) {
    DynamicBuffer<Byte> first = { 1, 2, 3 };
    DynamicBuffer<Byte&> second;
    second.insert(second.begin(), first.begin(), first.end());
    EXPECT_EQ(first.size(), second.size());

    for (Size i = 0; i < first.size(); ++i) {
        EXPECT_EQ(first[i], second[i]);
    }

    std::transform(first.begin(), first.end(), first.begin(), [](int i) { return i * 2; });

    for (Size i = 0; i < first.size(); ++i) {
        EXPECT_EQ(first[i], second[i]);
    }
}

TEST(DynamicBufferTest, destroy) {
    struct A {
        int& mC;
        int& mD;
        A(int& c, int& d) : mC(c), mD(d) { ++mC; };
        ~A() { ++mD; }

        A& operator=(const A& other) {
            mC = other.mC;
            mD = other.mD;
            return *this;
        }

        A(const A& other) : mC(other.mC), mD(other.mD) {}
    };

    int c = 0;
    int d = 0;
    {
        DynamicBuffer<A> db;
        db.emplaceBack(c, d);
        EXPECT_EQ(1, c);
        EXPECT_EQ(0, d);
    }
    EXPECT_EQ(1, c);
    EXPECT_EQ(1, d);
}

} // namespace crypto
