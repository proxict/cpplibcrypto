#ifndef COMMON_STATICBYTEBUFFER_H_
#define COMMON_STATICBYTEBUFFER_H_

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
    /// \param last Iterator pointing right after the last element to be removed. This means the last element within the
    /// range will not be erased.
    /// \returns Iterator to the next element after the last removed
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
    /// \param last Iterator pointing right after the last element to be inserted. This means the last element within
    /// the range will not be inserted. \returns Iterator pointing to the first inserted element
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
    /// If the requested size is less than the current size, the last elements will be erased to fulfil the size
    /// requirement. If the requested size is more than the current size, default constructed elements will be inserted.
    /// Asserts newSize to be less or equal to the buffer capacity.
    /// \param newSize The requested new size
    virtual void resize(const Size newSize) = 0;

    /// This is only an interface-compatibility function
    ///
    /// Asserts the requested capacity to be less or equal to the initial buffer capacity
    /// \returns Actual buffer capacity
    virtual Size reserve(const Size newCapacity) = 0;

    /// Inserts the elements from the given buffer at the end of this buffer
    /// \param b The buffer to be inserted
    /// \returns Reference to this object
    virtual StaticBufferBase& operator+=(const StaticBufferBase& b) = 0;

    /// Appends new element to the end of the buffer
    /// \param e The element to be inserted
    /// \returns Reference to this object
    virtual StaticBufferBase& operator+=(ConstReference e) = 0;
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

    explicit StaticBuffer() : mStored(0) {}

    explicit StaticBuffer(const Size count) : StaticBuffer() {
        ASSERT(count <= TCapacity);
        resize(count);
    }

    StaticBuffer(const Size count, ConstReference value)
    : StaticBuffer() {
        ASSERT(count <= TCapacity);
        insert(end(), value, count);
    }

    template <typename TIterator>
    StaticBuffer(TIterator first, TIterator last) : StaticBuffer() {
        ASSERT(Size(std::distance(first, last)) <= TCapacity);
        insert(end(), first, last);
    }

    explicit StaticBuffer(std::initializer_list<ValueType> list) : StaticBuffer(list.begin(), list.end()) {}

    explicit StaticBuffer(StaticBuffer&& other) { *this = std::move(other); }

    StaticBuffer& operator=(StaticBuffer&& other) {
        std::swap(mWipe, other.mWipe);
        std::swap(mData, other.mData);
        std::swap(mStored, other.mStored);
        return *this;
    }

    ~StaticBuffer() {
        clear();
        if (mWipe) {
            for (auto it : *this) {
                memory::wipe(&it);
            }
        }
    }

    void setSensitive(const bool sensitive = true) {
        mWipe = sensitive;
    }

    bool isSensitive() const {
        return mWipe;
    }

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

    Iterator erase(const Iterator first, const Iterator last) override {
        ASSERT(first >= begin() && last <= end());
        memory::destroy(first, last);
        std::move(last, end(), first);
        mStored -= std::distance(first, last);
        return first;
    }

    Iterator erase(const Size from, const Size count = 1) override {
        return erase(begin() + from, begin() + from + count);
    }

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

    Iterator insert(const Iterator position, ConstReference value, const Size count = 1U) override {
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

    Iterator insert(const Size position, ConstReference value, const Size count = 1U) override {
        return insert(begin() + position, value, count);
    }

    Iterator replace(const Iterator first, const Iterator last, const ConstIterator source) {
        memory::destroy(first, last);
        memory::constructRange<ValueType>(first, last, source);
        return first;
    }

    void pop() override {
        memory::destroy(back());
        --mStored;
    }

    void resize(const Size newSize) override {
        ASSERT(newSize <= TCapacity);
        if (newSize < mStored) {
            erase(begin() + newSize, end());
        } else if (newSize > mStored) {
            insert(end(), ValueType(), newSize - mStored);
        }
    }

    Size reserve(const Size newCapacity) override {
        ASSERT(capacity() >= newCapacity);
        return capacity();
    }

    Base& operator+=(const Base& b) override {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    Base& operator+=(ConstReference e) override {
        push(e);
        return *this;
    }

    const StaticBuffer operator+(const Base& rhs) const {
        StaticBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    const StaticBuffer operator+(ConstReference rhs) const {
        StaticBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

private:
    ValueType mData[TCapacity];
    Size mStored;
    bool mWipe = true;
};

template <typename T, Size TCapacity>
const StaticBuffer<T, TCapacity> operator+(const T& lhs, const StaticBufferBase<T>& rhs) {
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
