#ifndef COMMON_BYTEBUFFER_H_
#define COMMON_BYTEBUFFER_H_

#include <limits>
#include <utility>
#include <vector>

#include "common/Exception.h"
#include "common/LinearIterator.h"
#include "common/SecureAllocator.h"

namespace crypto {

template <typename T>
class DynamicBuffer {
public:
    using Type = T;
    using Reference = Type&;
    using ConstReference = const Type&;
    using RValuetReference = Type&&;
    using Pointer = Type*;
    using ConstPointer = const Type*;
    using Iterator = LinearIterator<Type>;
    using ConstIterator = LinearIterator<const Type>;

    using value_type = Type;
    using size_type = Size;
    using reference = Reference;
    using const_reference = ConstReference;
    using pointer = Pointer;
    using const_pointer = ConstPointer;
    using iterator = Iterator;
    using const_iterator = ConstIterator;

    DynamicBuffer(const bool sensitive = true) : mAllocator(sensitive) {}

    explicit DynamicBuffer(const Size size, const bool sensitive = true) : mAllocator(sensitive) {
        reserve(size);
        for (Size i = 0; i < size; ++i) {
            push(Type());
        }
    }

    DynamicBuffer(std::initializer_list<Byte> list, const bool sensitive = true) : mAllocator(sensitive) {
        insert(begin(), list.begin(), list.end());
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
        memory::deallocate(mData);
    }

    void setSensitive(const bool sensitive) { mAllocator.setWipe(sensitive); }

    bool isSensitive() const { return mAllocator.isWipe(); }

    ConstReference get(const Size index) const { return mData[index]; }

    Reference get(const Size index) { return mData[index]; }

    ConstReference operator[](const Size index) const { return get(index); }

    Reference operator[](const Size index) { return get(index); }

    ConstReference back() const { return get(size() - 1); }

    Reference back() { return get(size() - 1); }

    ConstPointer data() const { return mData; }

    Pointer data() { return mData; }

    Iterator begin() { return Iterator(this, 0); }

    Iterator end() { return Iterator(this, size()); }

    ConstIterator begin() const { return cbegin(); }

    ConstIterator end() const { return cend(); }

    ConstIterator cbegin() const { return ConstIterator(this, 0); }

    ConstIterator cend() const { return ConstIterator(this, size()); }

    bool empty() const { return mSize == 0; }

    Size size() const { return mSize; }

    Size capacity() const { return mCapacity; }

    void clear() {
        destroy(begin(), end());
        mSize = 0;
    }

    void erase(const Size index) {
        ASSERT(index <= mSize);
        auto erased = begin() + index;
        std::move(erased + 1, end(), erased);
        pop();
    }

    // Maybe it's all wrong..
    void erase(const Size from, const Size count) {
        ASSERT(from + count <= mSize);
        for (Size i = 0; i < count; ++i) {
            mAllocator.destroy(get(from + i));
            mData[from + i] = std::move(mData[from + i + count]);
        }
        mSize -= count;
    }

    void allocateMemory(const Size size) {
        Pointer newData = mAllocator.allocate(size);
        std::move(begin(), end(), newData);
        if (mData) {
            mAllocator.destroy(mData);
        }
        mData = newData;
    }

    void reserve(const Size size) {
        if (capacity() < size) {
            mCapacity = std::max(size, capacity() + capacity() / 2);
            allocateMemory(mCapacity);
        }
        ASSERT(capacity() >= size);
    }

    template <typename... TArgs>
    void emplaceBack(TArgs&&... args) {
        reserve(size() + 1);
        mAllocator.construct(mData + mSize, std::forward<TArgs>(args)...);
        ++mSize;
    }

    void push(ConstReference value) { emplaceBack(value); }

    void push(RValuetReference value = Type()) {
        emplaceBack(std::move(value));
    }

    void pop() {
        mAllocator.destroy(back());
        --mSize;
    }

    DynamicBuffer& operator+=(const DynamicBuffer& b) {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    DynamicBuffer& operator+=(const Byte b) {
        push(b);
        return *this;
    }

    const DynamicBuffer operator+(const DynamicBuffer& rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    const DynamicBuffer operator+(const Byte rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    friend const DynamicBuffer operator+(const Byte lhs, const DynamicBuffer& rhs) {
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

    template <typename TInputIterator, typename = std::_RequireInputIter<TInputIterator>>
    iterator insert(ConstIterator position, TInputIterator first, TInputIterator last) {
        const Size length = std::distance(first, last);
        reserve(size() + length);
        for (TInputIterator it = first; it != last; ++it) {
            push(*it);
        }
        return end();
    }

private:
    Pointer mData = nullptr;
    Size mSize = 0;
    Size mCapacity = 0;
    SecureAllocator<Type> mAllocator;
};

using ByteBuffer = DynamicBuffer<Byte>;

} // namespace crypto

#endif // COMMON_BYTEBUFFER_H_
