#ifndef COMMON_LINEARITERATOR_H_
#define COMMON_LINEARITERATOR_H_

#include <cstddef>
#include <iterator>

#include "common/TypeTraits.h"
#include "common/common.h"

namespace crypto {

template <class T>
class LinearIterator {
    using ValueType = T;
    using Pointer = ValueType*;

protected:
    Pointer mPtr;

public:
    // TODO(ProXicT): Size index() const; // return an offset from the beginning
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

    ValueType& data() { return *mPtr; }

    ValueType& operator*() { return data(); }

    const ValueType& data() const { return *mPtr; }

    const ValueType& operator*() const { return data(); }

    ValueType& operator[](const int offset) { return mPtr[offset]; }

    const ValueType& operator[](const int offset) const { return mPtr[offset]; }

    ValueType& operator[](const Size offset) { return mPtr[offset]; }

    const ValueType& operator[](const Size offset) const { return mPtr[offset]; }

    ValueType* operator->() { return (&**this); }

    const ValueType* operator->() const { return (&**this); }

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

    operator const Pointer() const {
        return mPtr;
    }

    operator Pointer() {
        return mPtr;
    }

    using iterator_category = std::random_access_iterator_tag;
    using value_type = ValueType;
    using difference_type = ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;
};

} // namespace crypto

#endif
