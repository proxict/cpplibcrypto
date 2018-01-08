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

    virtual ConstReference at(const Size index) const = 0;

    virtual Reference at(const Size index) = 0;

    virtual ConstReference operator[](const Size index) const = 0;

    virtual Reference operator[](const Size index) = 0;

    virtual ConstReference front() const = 0;

    virtual Reference front() = 0;

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

    virtual Iterator erase(const Size index) = 0;

    virtual Iterator erase(const Iterator first, const Iterator last) = 0;

    virtual Iterator erase(const Size from, const Size count) = 0;

    virtual void push(ConstReference value) = 0;

    virtual Iterator insert(const Iterator position, ConstPointer first, ConstPointer last) = 0;

    virtual Iterator insert(const Size position, ConstReference value) = 0;

    virtual void pop() = 0;

    virtual void resize(const Size newSize) = 0;

    virtual Size reserve(const Size newCapacity) = 0;

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

    ConstReference at(const Size index) const override { return mData[index]; }

    Reference at(const Size index) override { return mData[index]; }

    ConstReference operator[](const Size index) const override { return at(index); }

    Reference operator[](const Size index) override { return at(index); }

    ConstReference front() const override { return at(0); }

    Reference front() override { return at(0); }

    ConstReference back() const override { return at(size() - 1); }

    Reference back() override { return at(size() - 1); }

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

    Iterator erase(const Size index) override {
        ASSERT(index <= mStored);
        auto erased = begin() + index;
        std::move(erased + 1, end(), erased);
        pop();
        return erased;
    }

    Iterator erase(const Iterator first, const Iterator last) override {
        ASSERT(first >= begin() && last <= end());
        memory::destroy(first, last);
        std::move(last, end(), first);
        mStored -= std::distance(first, last);
        return first;
    }

    Iterator erase(const Size from, const Size count) override { return erase(begin() + from, begin() + from + count); }

    void push(ConstReference value) override {
        ASSERT(!full());
        at(size()) = value;
        ++mStored;
    }

    Iterator insert(const Iterator position, ConstPointer first, ConstPointer last) override {
        const Size length = std::distance(first, last);
        ASSERT(size() + length <= TCapacity);
        if (length < 1U) {
            return position;
        }

        Size offset = position - begin();
        std::move_backward(position, end(), end() + length);
        for (ConstPointer it = first; it != last; ++it) {
            memory::construct<ValueType>(begin() + offset, *it);
            ++offset;
        }
        mStored += length;
        return position;
    }

    Iterator insert(const Size position, ConstReference value) override {
        reserve(size() + 1);
        std::move_backward(begin() + position, end(), end() + 1);
        at(position) = value;
        ++mStored;
        return begin() + position;
    }

    void replace(const Iterator first, const Iterator last, const ConstIterator source) {
        memory::destroy(first, last);
        memory::constructRange<ValueType>(first, last, source);
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

    Size reserve(const Size newCapacity) override {
        ASSERT(capacity() >= newCapacity);
        return capacity();
    }

    Base& operator+=(const Base& b) override {
        insert(end(), b.begin(), b.end());
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

template <typename T>
bool operator==(const StaticBufferBase<T>& lhs, const StaticBufferBase<T>& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (Size i = 0; i < lhs.size(); ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }

    return true;
}

} // namespace crypto

#endif
