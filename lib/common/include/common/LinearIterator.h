#ifndef COMMON_LINEARITERATOR_H_
#define COMMON_LINEARITERATOR_H_

#include <cstddef>
#include <iterator>

#include "common/TypeTraits.h"

namespace crypto {

template <class T>
class LinearIterator {
    using Type = T;
    using TypePtr = Type*;

protected:
    TypePtr mPtr;

public:
    template <class T2>
    LinearIterator(T2* array, const Size ptr) : mPtr(array->data() + ptr) {}

    LinearIterator(TypePtr ptr, const Size offset) : mPtr(ptr + offset) {}

    explicit LinearIterator(TypePtr ptr) : mPtr(ptr) {}

    LinearIterator() = default;

    template <typename T2 = Type>
    operator DisableIf<IsConst<T2>::value, LinearIterator<const Type>>() const {
        return *(LinearIterator<const Type>*)this;
    }

    bool operator==(const LinearIterator& other) const { return mPtr == other.mPtr; }

    bool operator!=(const LinearIterator& other) const { return !((*this) == other); }

    bool operator<(const LinearIterator& other) const { return mPtr < other.mPtr; }

    bool operator>(const LinearIterator& other) const { return mPtr > other.mPtr; }

    bool operator<=(const LinearIterator& other) const { return mPtr <= other.mPtr; }

    bool operator>=(const LinearIterator& other) const { return mPtr >= other.mPtr; }

    ptrdiff_t operator-(const LinearIterator& other) const { return mPtr - other.mPtr; }

    Type& data() { return *mPtr; }

    Type& operator*() { return data(); }

    const Type& data() const { return *mPtr; }

    const Type& operator*() const { return data(); }

    Type& operator[](const int offset) { return mPtr[offset]; }

    const Type& operator[](const int offset) const { return mPtr[offset]; }

    Type& operator[](const Size offset) { return mPtr[offset]; }

    const Type& operator[](const Size offset) const { return mPtr[offset]; }

    Type* operator->() { return (&**this); }

    const Type* operator->() const { return (&**this); }

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

    operator const TypePtr() const {
        return mPtr;
    }

    operator TypePtr() {
        return mPtr;
    }

    using iterator_category = std::random_access_iterator_tag;
    using value_type = Type;
    using difference_type = ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;
};

} // namespace crypto

#endif
