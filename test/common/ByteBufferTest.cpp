#include <memory>

#include "gtest/gtest.h"

#include "common/ByteBuffer.h"
#include "common/HexString.h"

namespace crypto {

TEST(ByteBufferTest, basic) {
    ByteBuffer bb;
    bb += 0xab;
    bb += 0xac;

    EXPECT_EQ(0xab, bb[0]);
    EXPECT_EQ(0xac, bb[1]);
}

TEST(ByteBufferTest, chaining) {
    ByteBuffer bb;

    ByteBuffer bb1;
    bb1 += 0xab;
    bb1 += 0xcd;

    ByteBuffer bb2;
    bb2 += 0xef;
    bb2 += 0xff;

    bb += 0x00 + bb1 + bb2 + 0x0f;

    EXPECT_EQ(ByteBuffer({0x00, 0xab, 0xcd, 0xef, 0xff, 0x0f}), bb);
}

} // namespace crypto
