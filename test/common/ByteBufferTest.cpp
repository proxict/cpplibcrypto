#include <memory>

#include "gtest/gtest.h"

#include "common/DynamicBuffer.h"
#include "common/HexString.h"

namespace crypto {

TEST(ByteBufferTest, ctor) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_EQ(5U, bb.size());

    EXPECT_EQ(0x01, bb[0]);
    EXPECT_EQ(0x02, bb[1]);
    EXPECT_EQ(0x03, bb[2]);
    EXPECT_EQ(0x04, bb[3]);
    EXPECT_EQ(0x05, bb[4]);
}

TEST(ByteBufferTest, basic) {
    ByteBuffer bb;
    bb += 0xab;
    bb += 0xac;

    EXPECT_EQ(0xab, bb[0]);
    EXPECT_EQ(0xac, bb[1]);
}

TEST(ByteBufferTest, chaining) {
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

TEST(ByteBufferTest, eraseElement) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05};
    bb.erase(2);

    EXPECT_EQ(4U, bb.size());
    EXPECT_EQ(ByteBuffer({0x01, 0x02, 0x04, 0x05}), bb);
}

TEST(ByteBufferTest, eraseElements) {
    ByteBuffer bb{0x01, 0x02, 0x03, 0x04, 0x05};
    bb.erase(1, 3);

    EXPECT_EQ(2U, bb.size());
    EXPECT_EQ(ByteBuffer({0x01, 0x05}), bb);
}

TEST(ByteBufferTest, insertElement) {
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

TEST(ByteBufferTest, destroy) {
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
