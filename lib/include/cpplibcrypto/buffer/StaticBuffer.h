#ifndef CPPLIBCRYPTO_BUFFER_STATICBYTEBUFFER_H_
#define CPPLIBCRYPTO_BUFFER_STATICBYTEBUFFER_H_

#include "cpplibcrypto/buffer/utils/LinearIterator.h"
#include "cpplibcrypto/common/Memory.h"
#include "cpplibcrypto/common/common.h"

#include <utility>

NAMESPACE_CRYPTO_BEGIN

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

    virtual ~StaticBufferBase() = default;

    /// Returns a const reference to the data at the given index
    virtual ConstReference at(const Size index) const = 0;

    /// Returns a reference to the data at the given index
    virtual Reference at(const Size index) = 0;

    /// Returns a const reference to the data at the given index
    virtual ConstReference operator[](const Size index) const = 0;

    /// Returns a reference to the data at the given index
    virtual Reference operator[](const Size index) = 0;

    /// Returns a const reference to the first element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    virtual ConstReference front() const = 0;

    /// Returns a reference to the first element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    virtual Reference front() = 0;

    /// Returns a const reference to the last element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    virtual ConstReference back() const = 0;

    /// Returns a reference to the last element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    virtual Reference back() = 0;

    /// Returns a const pointer to the beginning
    virtual ConstPointer data() const = 0;

    /// Returns a pointer to the beginning
    virtual Pointer data() = 0;

    /// Returns an iterator to the beginning
    virtual Iterator begin() = 0;

    /// Returns an iterator to the end
    virtual Iterator end() = 0;

    /// Returns a const iterator to the beginning
    virtual ConstIterator begin() const = 0;

    /// Returns a const iterator to the end
    virtual ConstIterator end() const = 0;

    /// Returns a const iterator to the beginning
    virtual ConstIterator cbegin() const = 0;

    /// Returns a const iterator to the end
    virtual ConstIterator cend() const = 0;

    /// Returns whether or not the buffer is empty
    virtual bool empty() const = 0;

    /// Tells whether or not the buffer is full
    ///
    /// This means the size reached the buffer capacity
    virtual bool full() const = 0;

    /// Returns the actual size of the buffer
    virtual Size size() const = 0;

    /// Returns the buffer capacity
    virtual Size capacity() const = 0;

    /// Destroys all the elements in the buffer
    virtual void clear() = 0;

    /// Erases elements within the specified range
    ///
    /// \param first Iterator to the first element to be removed
    /// \param last Iterator pointing right after the last element to be removed. This means the last element
    /// within the range will not be erased. \returns Iterator to the next element after the last removed
    virtual Iterator erase(const Iterator first, const Iterator last) = 0;

    /// Erases the specified number of elements from the specified position
    ///
    /// \param from The first element to be removed
    /// \param count The number of elements to remove
    virtual Iterator erase(const Size from, const Size count = 1) = 0;

    /// Appends new element to the end of the buffer
    ///
    /// The element will be copy constructed from value
    /// \param value The value to append
    virtual void push(ConstReference value) = 0;

    /// Inserts the elements specified by the iterator range to the given position
    /// \param position The position where to insert the elements
    /// \param first Iterator to the first element to be inserted
    /// \param last Iterator pointing right after the last element to be inserted. This means the last element
    /// within the range will not be inserted. \returns Iterator pointing to the first inserted element
    virtual Iterator insert(const Iterator position, ConstPointer first, ConstPointer last) = 0;

    /// Inserts elements at the specified position
    /// \param position The position where to insert the elements
    /// \param value The value to be inserted
    /// \param count Tells how many times the value should be inserted
    /// \returns Iterator pointing to the first inserted element
    virtual Iterator insert(const Iterator position, ConstReference value, const Size count = 1U) = 0;

    /// \copydoc insert(const Iterator position, ConstReference value, const Size count = 1U)
    virtual Iterator insert(const Size position, ConstReference value, const Size count = 1U) = 0;

    /// Removes the last element
    ///
    /// Calling this function on an empty buffer is undefined
    virtual void pop() = 0;

    /// Resizes the buffer to the specified size
    ///
    /// If the requested size is less than the current size, the last elements will be erased to fulfil the
    /// size requirement. If the requested size is more than the current size, default constructed elements
    /// will be inserted. Asserts newSize to be less or equal to the buffer capacity. \param newSize The
    /// requested new size
    virtual void resize(const Size newSize) = 0;

    /// This is only an interface-compatibility function
    ///
    /// Asserts the requested capacity to be less or equal to the initial buffer capacity
    /// \returns Actual buffer capacity
    virtual Size reserve(const Size newCapacity) = 0;

    /// \copydoc push()
    StaticBufferBase& operator<<(ConstReference v) {
        push(v);
        return *this;
    }

    /// Inserts all elements from the given buffer to the end of this buffer
    StaticBufferBase& operator<<(const StaticBufferBase& v) {
        reserve(size() + v.size());
        insert(end(), v.begin(), v.end());
        return *this;
    }
};

template <typename T, Size TCapacity>
class StaticBuffer final : public StaticBufferBase<T> {
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

    constexpr explicit StaticBuffer()
        : mStored(0) {}

    constexpr explicit StaticBuffer(const Size count)
        : StaticBuffer() {
        ASSERT(count <= TCapacity);
        resize(count);
    }

    constexpr StaticBuffer(const Size count, ConstReference value)
        : StaticBuffer() {
        ASSERT(count <= TCapacity);
        insert(end(), value, count);
    }

    template <typename TIterator>
    constexpr StaticBuffer(TIterator first, TIterator last)
        : StaticBuffer() {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        insert(end(), first, last);
    }

    constexpr explicit StaticBuffer(std::initializer_list<ValueType> list)
        : StaticBuffer(list.begin(), list.end()) {}

    constexpr StaticBuffer(StaticBuffer&& other) { *this = std::move(other); }

    constexpr StaticBuffer& operator=(StaticBuffer&& other) {
        std::swap(mWipe, other.mWipe);
        std::swap(mData, other.mData);
        std::swap(mStored, other.mStored);
        return *this;
    }

    ~StaticBuffer() {
        Iterator first = begin();
        Iterator last = end();
        clear();
        if (mWipe) {
            for (Iterator it = first; it != last; ++it) {
                memory::wipe(&*it);
            }
        }
    }

    constexpr void setSensitive(const bool sensitive = true) { mWipe = sensitive; }

    constexpr bool isSensitive() const { return mWipe; }

    constexpr ConstReference at(const Size index) const override {
        ASSERT(index <= mStored);
        return mData[index];
    }

    constexpr Reference at(const Size index) override {
        ASSERT(index <= mStored);
        return mData[index];
    }

    constexpr ConstReference operator[](const Size index) const override { return at(index); }

    constexpr Reference operator[](const Size index) override { return at(index); }

    constexpr ConstReference front() const override { return at(0); }

    constexpr Reference front() override { return at(0); }

    constexpr ConstReference back() const override { return at(size() - 1); }

    constexpr Reference back() override { return at(size() - 1); }

    constexpr ConstPointer data() const override { return mData; }

    constexpr Pointer data() override { return mData; }

    constexpr Iterator begin() override { return Iterator(data()); }

    constexpr Iterator end() override { return Iterator(data(), size()); }

    constexpr ConstIterator begin() const override { return cbegin(); }

    constexpr ConstIterator end() const override { return cend(); }

    constexpr ConstIterator cbegin() const override { return ConstIterator(data()); }

    constexpr ConstIterator cend() const override { return ConstIterator(data(), size()); }

    constexpr bool empty() const override { return mStored == 0; }

    constexpr bool full() const override { return mStored >= TCapacity; }

    constexpr Size size() const override { return mStored; }

    constexpr Size capacity() const override { return TCapacity; }

    constexpr void clear() override {
        memory::destroy(begin(), end());
        mStored = 0;
    }

    constexpr Iterator erase(const Iterator first, const Iterator last) override {
        ASSERT(first >= begin() && last <= end());
        memory::destroy(first, last);
        std::move(last, end(), first);
        mStored -= std::distance(first, last);
        return first;
    }

    constexpr Iterator erase(const Size from, const Size count = 1) override {
        return erase(begin() + from, begin() + from + count);
    }

    constexpr void push(ConstReference value) override {
        ASSERT(!full());
        at(size()) = value;
        ++mStored;
    }

    constexpr Iterator insert(const Iterator position, ConstPointer first, ConstPointer last) override {
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

    constexpr Iterator insert(const Iterator position, ConstReference value, const Size count = 1U) override {
        const Size offset = position - begin();
        reserve(size() + count);
        Iterator pos = begin() + offset;
        std::move_backward(pos, end(), end() + count);
        for (Size i = 0; i < count; ++i) {
            memory::construct<ValueType>(pos++, value);
        }
        mStored += count;
        return pos;
    }

    constexpr Iterator insert(const Size position, ConstReference value, const Size count = 1U) override {
        return insert(begin() + position, value, count);
    }

    constexpr Iterator replace(const Iterator first, const Iterator last, const ConstIterator source) {
        memory::destroy(first, last);
        memory::constructRange<ValueType>(first, last, source);
        return first;
    }

    constexpr void pop() override {
        ASSERT(!empty());
        memory::destroy(back());
        --mStored;
    }

    constexpr void resize(const Size newSize) override {
        ASSERT(newSize <= TCapacity);
        if (newSize < mStored) {
            erase(begin() + newSize, end());
        } else if (newSize > mStored) {
            insert(end(), ValueType(), newSize - mStored);
        }
    }

    constexpr Size reserve(const Size newCapacity) override {
        ASSERT(capacity() >= newCapacity);
        return capacity();
    }

private:
    ValueType mData[TCapacity];
    Size mStored = 0;
    bool mWipe = true;
};

template <typename T>
constexpr bool operator==(const StaticBufferBase<T>& lhs, const StaticBufferBase<T>& rhs) {
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

NAMESPACE_CRYPTO_END

#endif
