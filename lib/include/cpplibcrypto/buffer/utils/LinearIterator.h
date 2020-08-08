#ifndef CPPLIBCRYPTO_BUFFER_UTILS_LINEARITERATOR_H_
#define CPPLIBCRYPTO_BUFFER_UTILS_LINEARITERATOR_H_

#include "cpplibcrypto/common/TypeTraits.h"
#include "cpplibcrypto/common/common.h"

#include <cstddef>
#include <iterator>

NAMESPACE_CRYPTO_BEGIN

template <class T>
class LinearIterator {
public:
    using ValueType = T;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
    using RValuetReference = ValueType&&;
    using Pointer = ValueType*;
    using ConstPointer = const ValueType*;

    using iterator_category = std::random_access_iterator_tag;
    using value_type = ValueType;
    using difference_type = ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    constexpr LinearIterator(Pointer ptr, const Size offset)
        : mPtr(ptr + offset) {}

    constexpr explicit LinearIterator(Pointer ptr)
        : mPtr(ptr) {}

    constexpr LinearIterator() = default;

    virtual ~LinearIterator() = default;

    template <typename T2 = ValueType>
    constexpr operator DisableIf<IsConst<T2>::value, LinearIterator<const ValueType>>() const {
        return *(LinearIterator<const ValueType>*)this;
    }

    constexpr bool operator==(const LinearIterator& other) const { return mPtr == other.mPtr; }

    constexpr bool operator!=(const LinearIterator& other) const { return !((*this) == other); }

    constexpr bool operator<(const LinearIterator& other) const { return mPtr < other.mPtr; }

    constexpr bool operator>(const LinearIterator& other) const { return mPtr > other.mPtr; }

    constexpr bool operator<=(const LinearIterator& other) const { return mPtr <= other.mPtr; }

    constexpr bool operator>=(const LinearIterator& other) const { return mPtr >= other.mPtr; }

    constexpr ptrdiff_t operator-(const LinearIterator& other) const { return mPtr - other.mPtr; }

    constexpr Reference data() { return *mPtr; }

    constexpr Reference operator*() { return data(); }

    constexpr ConstReference data() const { return *mPtr; }

    constexpr ConstReference operator*() const { return data(); }

    constexpr Reference operator[](const int offset) { return mPtr[offset]; }

    constexpr ConstReference operator[](const int offset) const { return mPtr[offset]; }

    constexpr Reference operator[](const Size offset) { return mPtr[offset]; }

    constexpr ConstReference operator[](const Size offset) const { return mPtr[offset]; }

    constexpr Pointer operator->() { return (&**this); }

    constexpr ConstPointer operator->() const { return (&**this); }

    constexpr LinearIterator& operator++() {
        ++mPtr;
        return *this;
    }

    constexpr LinearIterator operator++(int) {
        LinearIterator temp = *this;
        ++mPtr;
        return temp;
    }

    constexpr LinearIterator& operator--() {
        --mPtr;
        return *this;
    }

    constexpr LinearIterator operator--(int) {
        LinearIterator temp = *this;
        --mPtr;
        return temp;
    }

    constexpr LinearIterator& operator+=(const Size x) {
        mPtr += x;
        return *this;
    }

    constexpr LinearIterator& operator-=(const Size x) {
        mPtr -= x;
        return *this;
    }

    constexpr LinearIterator operator+(const Size x) const {
        LinearIterator res(*this);
        res.mPtr += x;
        return res;
    }

    constexpr LinearIterator operator-(const Size x) const {
        LinearIterator res(*this);
        res.mPtr -= x;
        return res;
    }

    constexpr operator Pointer() const { return mPtr; }

    constexpr operator Pointer() { return mPtr; }

protected:
    Pointer mPtr;
};

NAMESPACE_CRYPTO_END

#endif
