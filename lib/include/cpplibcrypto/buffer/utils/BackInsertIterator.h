#ifndef CPPLIBCRYPTO_BUFFER_UTILS_BACKINSERTITERATOR_H_
#define CPPLIBCRYPTO_BUFFER_UTILS_BACKINSERTITERATOR_H_

#include "cpplibcrypto/common/TypeTraits.h"
#include "cpplibcrypto/common/common.h"

#include <cstddef>
#include <iterator>

namespace crypto {

template <typename TBuffer>
class BackInsertIterator {
public:
    using ValueType = typename TBuffer::ValueType;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
    using RValuetReference = ValueType&&;
    using Pointer = ValueType*;
    using ConstPointer = const ValueType*;

    using iterator_category = std::output_iterator_tag;
    using value_type = ValueType;
    using difference_type = ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    constexpr BackInsertIterator() noexcept = default;

    explicit constexpr BackInsertIterator(TBuffer& buffer)
        : mBuffer(std::addressof(buffer)) {}

    constexpr BackInsertIterator& operator=(const ValueType& value) {
        pushBack(value);
        return *this;
    }

    constexpr BackInsertIterator& operator=(ValueType&& value) {
        pushBack(std::move(value));
        return *this;
    }

    constexpr BackInsertIterator& operator*() { return *this; }

    constexpr BackInsertIterator& operator++() { return *this; }

    constexpr BackInsertIterator operator++(int) { return *this; }

private:
    template <typename T,
              typename TBuf = TBuffer,
              EnableIf<std::is_same<void, decltype(std::declval<TBuf>().push(ValueType()))>::value, char> = 0>
    constexpr void pushBack(T&& value) {
        mBuffer->push(std::forward<T>(value));
    }

    template <
        typename T,
        typename TBuf = TBuffer,
        EnableIf<std::is_same<void, decltype(std::declval<TBuf>().pushBack(ValueType()))>::value, char> = 0>
    constexpr void pushBack(T&& value) {
        mBuffer->pushBack(std::forward<T>(value));
    }

    template <
        typename T,
        typename TBuf = TBuffer,
        EnableIf<std::is_same<void, decltype(std::declval<TBuf>().push_back(ValueType()))>::value, char> = 0>
    constexpr void pushBack(T&& value) {
        mBuffer->push_back(std::forward<T>(value));
    }

    TBuffer* mBuffer = nullptr;
};

template <typename TBuffer>
constexpr BackInsertIterator<TBuffer> backInserter(TBuffer& buffer) {
    return BackInsertIterator<TBuffer>(buffer);
}

} // namespace crypto

#endif // CPPLIBCRYPTO_BUFFER_UTILS_BACKINSERTITERATOR_H_
