#include "gmock/gmock.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/utils/BackInsertIterator.h"

#include <algorithm>

NAMESPACE_CRYPTO_BEGIN

enum class Functions { UNDEFINED, PUSH, PUSHBACK, PUSH_BACK };
template <Functions TOverload>
struct Container {
    using ValueType = int;

    static constexpr Functions getCurrentOverload() {
        return TOverload;
    }

    template <Functions Fun = TOverload, EnableIf<Fun == Functions::PUSH, char> = 0>
    void push(const ValueType& value) {
        mBuffer.push(value);
        mCalledOverload = Functions::PUSH;
    }

    template <Functions Fun = TOverload, EnableIf<Fun == Functions::PUSHBACK, char> = 0>
    void pushBack(const ValueType& value) {
        mBuffer.push(value);
        mCalledOverload = Functions::PUSHBACK;
    }

    template <Functions Fun = TOverload, EnableIf<Fun == Functions::PUSH_BACK, char> = 0>
    void push_back(const ValueType& value) {
        mBuffer.push(value);
        mCalledOverload = Functions::PUSH_BACK;
    }

    std::size_t size() const { return mBuffer.size(); }

    const ValueType& at(const std::size_t index) const { return mBuffer.at(index); }

    DynamicBuffer<ValueType> mBuffer;
    Functions mCalledOverload = Functions::UNDEFINED;
};

template <typename T>
class BackInsertTest : public ::testing::Test {};

TYPED_TEST_SUITE_P(BackInsertTest);

TYPED_TEST_P(BackInsertTest, fill) {
    TypeParam c;
    std::fill_n(backInserter(c), 3, -1);

    EXPECT_EQ(DynamicBuffer<int>(3, -1), c.mBuffer);
    ASSERT_EQ(TypeParam::getCurrentOverload(), c.mCalledOverload);
}

TYPED_TEST_P(BackInsertTest, increment) {
    TypeParam c;
    auto it = backInserter(c);
    for (int i = 0; i < 5; ++i) {
        it++ = i;
    }

    EXPECT_EQ(DynamicBuffer<int>({ 0, 1, 2, 3, 4 }), c.mBuffer);
    ASSERT_EQ(TypeParam::getCurrentOverload(), c.mCalledOverload);
}

using ContainerTypes = ::testing::
    Types<Container<Functions::PUSH>, Container<Functions::PUSHBACK>, Container<Functions::PUSH_BACK>>;

REGISTER_TYPED_TEST_SUITE_P(BackInsertTest, fill, increment);
INSTANTIATE_TYPED_TEST_SUITE_P(BackInserter, BackInsertTest, ContainerTypes);

NAMESPACE_CRYPTO_END
