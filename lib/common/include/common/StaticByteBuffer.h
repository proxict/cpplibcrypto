#ifndef COMMON_STATICBYTEBUFFER_H_
#define COMMON_STATICBYTEBUFFER_H_

#include <iostream>
#include <utility>

#include "common/ByteBuffer.h"
#include "common/Exception.h"
#include "common/LinearIterator.h"
#include "common/common.h"

namespace crypto {

class StaticByteBufferBase {
public:
    using Type = byte;
    using Reference = Type&;
    using ConstReference = const Type&;
    using Pointer = Type*;
    using ConstPointer = const Type*;
    using Iterator = LinearIterator<Type>;
    using ConstIterator = LinearIterator<const Type>;
    using Size = std::size_t;

    using value_type = Type;
    using size_type = Size;
    using reference = Reference;
    using const_reference = ConstReference;
    using pointer = Pointer;
    using const_pointer = ConstPointer;
    using iterator = Iterator;
    using const_iterator = ConstIterator;

    StaticByteBufferBase() = default;
    virtual ~StaticByteBufferBase() {}

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

    virtual void insert(Pointer first, Pointer last) = 0;

    virtual void pop() = 0;

    virtual void resize(const Size newSize) = 0;
};

template <std::size_t TCapacity>
class StaticByteBuffer : public StaticByteBufferBase {
protected:
    Type mData[TCapacity];
    Size mStored;

public:
    StaticByteBuffer() : mStored(0) {}

    explicit StaticByteBuffer(const Size count) : StaticByteBuffer() {
        ASSERT(count <= TCapacity);
        for (Size i = 0; i < count; ++i) {
            mData[i] = Type();
        }

        mStored = count;
    }

    explicit StaticByteBuffer(const Size count, ConstReference value) : StaticByteBuffer() {
        ASSERT(count <= TCapacity);
        for (Size i = 0; i < count; ++i) {
            mData[i] = value;
        }

        mStored = count;
    }

    template <typename TIterator>
    StaticByteBuffer(TIterator first, TIterator last) : StaticByteBuffer() {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        for (auto it = first; it != last; ++it) {
            push(*it);
        }
    }

    StaticByteBuffer(StaticByteBuffer&& other) : StaticByteBuffer() {
        for (auto& it : other) {
            push(std::move(it));
        }
    }

    StaticByteBuffer& operator=(StaticByteBuffer&& other) {
        for (auto& it : other) {
            push(std::move(it));
        }
        return *this;
    }

    StaticByteBuffer(std::initializer_list<Type> list) : StaticByteBuffer(list.begin(), list.end()) {}

    ~StaticByteBuffer() { clear(); }

    ConstReference get(const Size index) const override { return mData[index]; }

    Reference get(const Size index) override { return mData[index]; }

    ConstReference operator[](const Size index) const override { return get(index); }

    Reference operator[](const Size index) override { return get(index); }

    ConstReference back() const override { return get(size() - 1); }

    Reference back() override { return get(size() - 1); }

    ConstPointer data() const override { return mData; }

    Pointer data() override { return mData; }

    Iterator begin() override { return Iterator(this, 0); }

    Iterator end() override { return Iterator(this, size()); }

    ConstIterator begin() const override { return cbegin(); }

    ConstIterator end() const override { return cend(); }

    ConstIterator cbegin() const override { return ConstIterator(this, 0); }

    ConstIterator cend() const override { return ConstIterator(this, size()); }

    bool empty() const override { return mStored == 0; }

    bool full() const override { return mStored == TCapacity; }

    Size size() const override { return mStored; }

    Size capacity() const override { return TCapacity; }

    void clear() override {
        destroy(begin(), end());
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
            destroy(mData[from + i]);
            mData[from + i] = std::move(mData[from + i + count]);
        }
        mStored -= count;
    }

    void push(ConstReference value) override {
        ASSERT(!full());
        mData[size()] = value;
        ++mStored;
    }

    void insert(Pointer first, Pointer last) override {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        for (auto it = first; it != last; ++it) {
            push(*it);
        }
    }

    void pop() override {
        destroy(back());
        --mStored;
    }

    void resize(const Size newSize) override {
        ASSERT(newSize <= TCapacity);
        if (newSize < mStored) {
            destroy(begin() + newSize, end());
        } else {
            for (Size i = mStored; i < newSize; ++i) {
                mData[i] = Type();
            }
        }
    }
};

} // namespace crypto

#endif
