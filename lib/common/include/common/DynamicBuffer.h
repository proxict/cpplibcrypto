#ifndef COMMON_BYTEBUFFER_H_
#define COMMON_BYTEBUFFER_H_

#include "common/Exception.h"
#include "common/LinearIterator.h"
#include "common/SecureAllocator.h"
#include <iostream>
#include <algorithm>

namespace crypto {

template <typename T, typename TAllocator = SecureAllocator<ReferenceStorage<T>>>
class DynamicBuffer final {
public:
    using ValueType = ReferenceStorage<T>;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
    using RValuetReference = ValueType&&;
    using Pointer = ValueType*;
    using ConstPointer = const ValueType*;
    using Iterator = LinearIterator<ValueType>;
    using ConstIterator = LinearIterator<const ValueType>;

    using value_type = ValueType;
    using size_type = Size;
    using reference = Reference;
    using const_reference = ConstReference;
    using pointer = Pointer;
    using const_pointer = ConstPointer;
    using iterator = Iterator;
    using const_iterator = ConstIterator;

    explicit DynamicBuffer(const bool sensitive = true) : mAllocator(sensitive) {}

    explicit DynamicBuffer(const Size size, const bool sensitive = true) : mAllocator(sensitive) {
        reserve(size);
        for (Size i = 0; i < size; ++i) {
            push(ValueType());
        }
    }

    DynamicBuffer(std::initializer_list<ValueType> list, const bool sensitive = true) : mAllocator(sensitive) {
        reserve(list.size());
        insert(end(), list.begin(), list.end());
    }

    DynamicBuffer& operator=(DynamicBuffer&& other) noexcept {
        std::swap(mAllocator, other.mAllocator);
        std::swap(mData, other.mData);
        std::swap(mSize, other.mSize);
        std::swap(mCapacity, other.mCapacity);
        return *this;
    }

    DynamicBuffer(DynamicBuffer&& other) noexcept { *this = std::move(other); }

    ~DynamicBuffer() {
        clear();
        mAllocator.deallocate(mData, 0);
        mCapacity = 0;
    }

    void setSensitive(const bool sensitive) { mAllocator.setWipe(sensitive); }

    bool isSensitive() const { return mAllocator.isWipe(); }

    ConstReference at(const Size index) const { return mData[index]; }

    Reference at(const Size index) { return mData[index]; }

    ConstReference operator[](const Size index) const { return at(index); }

    Reference operator[](const Size index) { return at(index); }

    ConstReference front() const { return at(0); }

    Reference front() { return at(0); }

    ConstReference back() const { return at(size() - 1); }

    Reference back() { return at(size() - 1); }

    ConstPointer data() const { return mData; }

    Pointer data() { return mData; }

    Iterator begin() { return Iterator(data()); }

    Iterator end() { return Iterator(data(), size()); }

    ConstIterator begin() const { return cbegin(); }

    ConstIterator end() const { return cend(); }

    ConstIterator cbegin() const { return ConstIterator(data()); }

    ConstIterator cend() const { return ConstIterator(data(), size()); }

    bool empty() const { return mSize == 0; }

    Size size() const { return mSize; }

    Size capacity() const { return mCapacity; }

    void clear() {
        mAllocator.destroy(begin(), end());
        mSize = 0;
    }

    Iterator erase(const Iterator first, const Iterator last) {
        ASSERT(first >= begin() && last <= end());
        mAllocator.destroy(first, last);
        std::move(last, end(), first);
        mSize -= std::distance(first, last);
        return first;
    }

    Iterator erase(const Size from, const Size count = 1) { return erase(begin() + from, begin() + from + count); }

    Size reserve(const Size newCapacity) {
        if (capacity() >= newCapacity) {
            return capacity();
        }
        mCapacity = std::max(newCapacity, capacity() + capacity() / 2);
        allocateMemory(mCapacity);
        ASSERT(capacity() >= newCapacity);
        return capacity();
    }

    void resize(const Size newSize) {
        if (newSize == size()) {
            return;
        } else if (newSize < size()) {
            mAllocator.destroy(begin() + newSize, end());
        } else {
            reserve(newSize);
            for (Size i = 0; i < newSize - size(); ++i) {
                mAllocator.construct(mData + size() + i, ValueType());
            }
        }
        mSize = newSize;
    }

    template <typename... TArgs>
    void emplaceBack(TArgs&&... args) {
        reserve(size() + 1);
        mAllocator.construct(mData + size(), std::forward<TArgs>(args)...);
        ++mSize;
    }

    void push(ConstReference value) { emplaceBack(value); }

    void push(RValuetReference value = ValueType()) { emplaceBack(std::move(value)); }

    template <typename TInputIterator, typename = std::_RequireInputIter<TInputIterator>>
    Iterator insert(Iterator position, TInputIterator first, TInputIterator last) {
        ASSERT(position >= begin() && position <= end());
        const Size length = std::distance(first, last);
        if (first == last) {
            return position;
        }

        const Size offset = position - begin();
        reserve(size() + length);
        std::move_backward(begin() + offset, end(), end() + length);
        Size index = 0;
        for (TInputIterator it = first; it != last; ++it) {
            mAllocator.construct(begin() + offset + index, *it);
            ++index;
        }
        mSize += length;
        return position;
    }

    Iterator insert(const Size position, ConstReference value) {
        reserve(size() + 1);
        const Iterator pos = begin() + position;
        std::move_backward(pos, end(), end() + 1);
        mAllocator.construct(pos, value);
        ++mSize;
        return pos;
    }

    void replace(const Iterator first, const Iterator last, const ConstIterator source) {
        mAllocator.destroy(first, last);
        mAllocator.constructRange(first, last, source);
    }

    void pop() {
        mAllocator.destroy(back());
        --mSize;
    }

    DynamicBuffer& operator+=(const DynamicBuffer& b) {
        reserve(size() + b.size());
        insert(end(), b.begin(), b.end());
        return *this;
    }

    DynamicBuffer& operator+=(ConstReference b) {
        push(b);
        return *this;
    }

    const DynamicBuffer operator+(const DynamicBuffer& rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    const DynamicBuffer operator+(ConstReference rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    friend const DynamicBuffer operator+(ConstReference lhs, const DynamicBuffer& rhs) {
        DynamicBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    bool operator==(const DynamicBuffer& rhs) const {
        if (size() != rhs.size()) {
            return false;
        }
        for (Size i = 0; i < size(); ++i) {
            if ((*this)[i] != rhs[i]) {
                return false;
            }
        }
        return true;
    }

    bool operator!=(const DynamicBuffer& rhs) const { return !(*this == rhs); }

private:
    void allocateMemory(const Size size) {
        Pointer newData = mAllocator.allocate(size);
        std::move(begin(), end(), newData);
        if (mData) {
            mAllocator.destroy(mData);
        }
        mData = newData;
    }

private:
    Pointer mData = nullptr;
    Size mSize = 0;
    Size mCapacity = 0;
    TAllocator mAllocator;
};

using ByteBuffer = DynamicBuffer<Byte>;

} // namespace crypto

#endif // COMMON_BYTEBUFFER_H_
