#include <memory>

#include "gtest/gtest.h"

#include "common/ByteBuffer.h"
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

TEST(ByteBufferTest, destroy) {
    struct A {
        int& m;
        A(int& k) : m(k) { ++m; };
        virtual ~A() { ++m; }
    };

    struct B : public A {
        B(int& k) : A(k) { ++m; };
        ~B() { ++m; };
    };

    int k = 0;
    {
        DynamicBuffer<A*> db;
        db.emplaceBack(new A(k));
        EXPECT_EQ(2, k);
    }
    EXPECT_EQ(4, k);
}

} // namespace crypto
