#ifndef COMMON_LINEARITERATOR_H_
#define COMMON_LINEARITERATOR_H_

#include <cstddef>
#include <iterator>

#include "common/TypeTraits.h"
#include "common/common.h"

namespace crypto {

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

    LinearIterator(Pointer ptr, const Size offset) : mPtr(ptr + offset) {}

    explicit LinearIterator(Pointer ptr) : mPtr(ptr) {}

    LinearIterator() = default;

    template <typename T2 = ValueType>
    operator DisableIf<IsConst<T2>::value, LinearIterator<const ValueType>>() const {
        return *(LinearIterator<const ValueType>*)this;
    }

    bool operator==(const LinearIterator& other) const { return mPtr == other.mPtr; }

    bool operator!=(const LinearIterator& other) const { return !((*this) == other); }

    bool operator<(const LinearIterator& other) const { return mPtr < other.mPtr; }

    bool operator>(const LinearIterator& other) const { return mPtr > other.mPtr; }

    bool operator<=(const LinearIterator& other) const { return mPtr <= other.mPtr; }

    bool operator>=(const LinearIterator& other) const { return mPtr >= other.mPtr; }

    ptrdiff_t operator-(const LinearIterator& other) const { return mPtr - other.mPtr; }

    Reference data() { return *mPtr; }

    Reference operator*() { return data(); }

    ConstReference data() const { return *mPtr; }

    ConstReference operator*() const { return data(); }

    Reference operator[](const int offset) { return mPtr[offset]; }

    ConstReference operator[](const int offset) const { return mPtr[offset]; }

    Reference operator[](const Size offset) { return mPtr[offset]; }

    ConstReference operator[](const Size offset) const { return mPtr[offset]; }

    Pointer operator->() { return (&**this); }

    ConstPointer operator->() const { return (&**this); }

    LinearIterator& operator++() {
        ++mPtr;
        return *this;
    }

    LinearIterator operator++(int) {
        LinearIterator temp = *this;
        ++mPtr;
        return temp;
    }

    LinearIterator& operator--() {
        --mPtr;
        return *this;
    }

    LinearIterator operator--(int) {
        LinearIterator temp = *this;
        --mPtr;
        return temp;
    }

    LinearIterator& operator+=(const Size x) {
        mPtr += x;
        return *this;
    }

    LinearIterator& operator-=(const Size x) {
        mPtr -= x;
        return *this;
    }

    LinearIterator operator+(const Size x) const {
        LinearIterator res(*this);
        res.mPtr += x;
        return res;
    }

    LinearIterator operator-(const Size x) const {
        LinearIterator res(*this);
        res.mPtr -= x;
        return res;
    }

    operator const Pointer() const { return mPtr; }

    operator Pointer() { return mPtr; }

protected:
    Pointer mPtr;
};

} // namespace crypto

#endif
