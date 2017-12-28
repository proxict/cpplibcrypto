#ifndef COMMON_STATICBYTEBUFFER_H_
#define COMMON_STATICBYTEBUFFER_H_

#include <iostream>
#include <utility>

#include "common/Exception.h"
#include "common/LinearIterator.h"
#include "common/Memory.h"
#include "common/common.h"

namespace crypto {

template <typename T>
class StaticBufferBase {
public:
    using ValueType = T;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
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

    StaticBufferBase() = default;
    virtual ~StaticBufferBase() {}

    virtual ConstReference get(const Size index) const = 0;

    virtual Reference get(const Size index) = 0;

    virtual ConstReference operator[](const Size index) const = 0;

    virtual Reference operator[](const Size index) = 0;

    virtual ConstReference back() const = 0;

    virtual Reference back() = 0;

    virtual ConstPointer data() const = 0;

    virtual Pointer data() = 0;

    virtual Iterator begin() = 0;

    virtual Iterator end() = 0;

    virtual ConstIterator begin() const = 0;

    virtual ConstIterator end() const = 0;

    virtual ConstIterator cbegin() const = 0;

    virtual ConstIterator cend() const = 0;

    virtual bool empty() const = 0;

    virtual bool full() const = 0;

    virtual Size size() const = 0;

    virtual Size capacity() const = 0;

    virtual void clear() = 0;

    virtual void erase(const Size index) = 0;

    virtual void push(ConstReference value) = 0;

    virtual void insert(ConstPointer first, ConstPointer last) = 0;

    virtual void pop() = 0;

    virtual void resize(const Size newSize) = 0;

    virtual StaticBufferBase& operator+=(const StaticBufferBase& b) = 0;

    virtual StaticBufferBase& operator+=(const Byte b) = 0;
};

template <typename T, Size TCapacity>
class StaticBuffer : public StaticBufferBase<T> {
public:
    using Base = StaticBufferBase<T>;
    using ValueType = T;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
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

    StaticBuffer() : mStored(0) {}

    explicit StaticBuffer(const Size count) : StaticBuffer() {
        ASSERT(count <= TCapacity);
        for (Size i = 0; i < count; ++i) {
            mData[i] = ValueType();
        }

        mStored = count;
    }

    explicit StaticBuffer(const Size count, ConstReference value) : StaticBuffer() {
        ASSERT(count <= TCapacity);
        for (Size i = 0; i < count; ++i) {
            mData[i] = value;
        }

        mStored = count;
    }

    template <typename TIterator>
    StaticBuffer(TIterator first, TIterator last) : StaticBuffer() {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        for (auto it = first; it != last; ++it) {
            push(*it);
        }
    }

    StaticBuffer(StaticBuffer&& other) : StaticBuffer() {
        for (auto& it : other) {
            push(std::move(it));
        }
    }

    StaticBuffer& operator=(StaticBuffer&& other) {
        for (auto& it : other) {
            push(std::move(it));
        }
        return *this;
    }

    StaticBuffer(std::initializer_list<ValueType> list) : StaticBuffer(list.begin(), list.end()) {}

    ~StaticBuffer() { clear(); }

    ConstReference get(const Size index) const override { return mData[index]; }

    Reference get(const Size index) override { return mData[index]; }

    ConstReference operator[](const Size index) const override { return get(index); }

    Reference operator[](const Size index) override { return get(index); }

    ConstReference back() const override { return get(size() - 1); }

    Reference back() override { return get(size() - 1); }

    ConstPointer data() const override { return mData; }

    Pointer data() override { return mData; }

    Iterator begin() override { return Iterator(data()); }

    Iterator end() override { return Iterator(data(), size()); }

    ConstIterator begin() const override { return cbegin(); }

    ConstIterator end() const override { return cend(); }

    ConstIterator cbegin() const override { return ConstIterator(data()); }

    ConstIterator cend() const override { return ConstIterator(data(), size()); }

    bool empty() const override { return mStored == 0; }

    bool full() const override { return mStored == TCapacity; }

    Size size() const override { return mStored; }

    Size capacity() const override { return TCapacity; }

    void clear() override {
        memory::destroy(begin(), end());
        mStored = 0;
    }

    void erase(const Size index) override {
        ASSERT(index <= mStored);
        auto erased = begin() + index;
        std::move(erased + 1, end(), erased);
        pop();
    }

    // Maybe it's all wrong..
    void erase(const Size from, const Size count) {
        ASSERT(from + count <= mStored);
        for (Size i = 0; i < count; ++i) {
            memory::destroy(mData[from + i]);
            mData[from + i] = std::move(mData[from + i + count]);
        }
        mStored -= count;
    }

    void push(ConstReference value) override {
        ASSERT(!full());
        mData[size()] = value;
        ++mStored;
    }

    void insert(ConstPointer first, ConstPointer last) override {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        for (auto it = first; it != last; ++it) {
            push(*it);
        }
    }

    void pop() override {
        memory::destroy(back());
        --mStored;
    }

    void resize(const Size newSize) override {
        ASSERT(newSize <= TCapacity);
        if (newSize < mStored) {
            memory::destroy(begin() + newSize, end());
        } else {
            for (Size i = mStored; i < newSize; ++i) {
                mData[i] = ValueType();
            }
        }
        mStored = newSize;
    }

    Base& operator+=(const Base& b) override {
        insert(b.begin(), b.end());
        return *this;
    }

    Base& operator+=(const Byte b) override {
        push(b);
        return *this;
    }

    const StaticBuffer operator+(const Base& rhs) const {
        StaticBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    const StaticBuffer operator+(const Byte rhs) const {
        StaticBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

private:
    ValueType mData[TCapacity];
    Size mStored;
};

template <typename T, Size TCapacity>
const StaticBuffer<T, TCapacity> operator+(const Byte lhs, const StaticBufferBase<T>& rhs) {
    StaticBuffer<T, TCapacity> sbb;
    sbb += lhs;
    sbb += rhs;
    return sbb;
}

} // namespace crypto

#endif
