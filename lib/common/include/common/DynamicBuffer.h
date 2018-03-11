#ifndef COMMON_BYTEBUFFER_H_
#define COMMON_BYTEBUFFER_H_

#include "common/Exception.h"
#include "common/LinearIterator.h"
#include "common/SecureAllocator.h"

NAMESPACE_CRYPTO_BEGIN

/// Dynamically allocated buffer which also allowes to store references
///
/// Allows to be provided with a custom allocator
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

    /// By default the buffer is constructed with a sensitive flag
    /// For more information about the sensitive flag, \see setSensitive()
    DynamicBuffer() : mAllocator(true) {}

    /// Constructs the buffer with count default-inserted instances of ValueType. No copies are made.
    explicit DynamicBuffer(const Size size) : DynamicBuffer() { resize(size); }

    /// Constructs the buffer with \ref count copies of \ref value value
    explicit DynamicBuffer(const Size count, const ValueType& value) : DynamicBuffer() { insert(end(), value, count); }

    /// Constructs the buffer with the content of the initializer list
    DynamicBuffer(std::initializer_list<ValueType> list) : DynamicBuffer() { insert(end(), list.begin(), list.end()); }

    DynamicBuffer& operator=(std::initializer_list<ValueType> list) {
        clear();
        insert(end(), list.begin(), list.end());
        return *this;
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
        mData = nullptr;
        mCapacity = 0;
    }

    /// Sets the sensitive flag to the buffer
    ///
    /// Sensitive flag means that on destruction (which also includes reallocating the buffer) the data will not only be
    /// destroyed but also memset with a random bytes.
    void setSensitive(const bool sensitive = true) { mAllocator.setWipe(sensitive); }

    /// Returns whether or not the sensitive flag is set
    bool isSensitive() const { return mAllocator.isWipe(); }

    /// Returns a const reference to the data at the given index
    ConstReference at(const Size index) const { return mData[index]; }

    /// Returns a reference to the data at the given index
    Reference at(const Size index) { return mData[index]; }

    /// Returns a const reference to the data at the given index
    ConstReference operator[](const Size index) const { return at(index); }

    /// Returns a reference to the data at the given index
    Reference operator[](const Size index) { return at(index); }

    /// Returns a const reference to the first element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    ConstReference front() const { return at(0); }

    /// Returns a reference to the first element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    Reference front() { return at(0); }

    /// Returns a const reference to the last element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    ConstReference back() const { return at(size() - 1); }

    /// Returns a reference to the last element in the buffer
    ///
    /// The behaviour is undefined in case the buffer is empty.
    Reference back() { return at(size() - 1); }

    /// Returns a const pointer to the beginning
    ConstPointer data() const { return mData; }

    /// Returns a pointer to the beginning
    Pointer data() { return mData; }

    /// Returns an iterator to the beginning
    Iterator begin() { return Iterator(data()); }

    /// Returns an iterator to the end
    Iterator end() { return Iterator(data(), size()); }

    /// Returns a const iterator to the beginning
    ConstIterator begin() const { return cbegin(); }

    /// Returns a const iterator to the end
    ConstIterator end() const { return cend(); }

    /// Returns a const iterator to the beginning
    ConstIterator cbegin() const { return ConstIterator(data()); }

    /// Returns a const iterator to the end
    ConstIterator cend() const { return ConstIterator(data(), size()); }

    /// Returns whether or not the buffer is empty
    bool empty() const { return mSize == 0; }

    /// Returns the actual size of the buffer
    Size size() const { return mSize; }

    /// Returns the buffer capacity
    Size capacity() const { return mCapacity; }

    /// Destroys all the elements in the buffer
    ///
    /// The size after calling this function will be zero, however, the capacity will not be changed
    void clear() {
        mAllocator.destroy(begin(), end());
        mSize = 0;
    }

    /// Erases elements within the specified range
    ///
    /// \param first Iterator to the first element to be removed
    /// \param last Iterator pointing right after the last element to be removed. This means the last element within the
    /// range will not be erased.
    /// \returns Iterator to the next element after the last removed
    Iterator erase(const Iterator first, const Iterator last) {
        ASSERT(first >= begin() && last <= end());
        mAllocator.destroy(first, last);
        std::move(last, end(), first);
        mSize -= std::distance(first, last);
        return first;
    }

    /// Erases the specified number of elements from the specified position
    ///
    /// \param from The first element to be removed
    /// \param count The number of elements to remove
    Iterator erase(const Size from, const Size count = 1) { return erase(begin() + from, begin() + from + count); }

    /// Reserves a capacity for the specified number of elements
    ///
    /// If the specified capacity is less or equal to the current capacity, the function is no-op.
    /// \param newCapacity The requested capacity to allocate
    /// \returns The actual capacity
    Size reserve(const Size newCapacity) {
        if (capacity() >= newCapacity) {
            return capacity();
        }
        mCapacity = std::max(newCapacity, capacity() + capacity() / 2);
        allocateMemory(mCapacity);
        ASSERT(capacity() >= newCapacity);
        return capacity();
    }

    /// Resizes the buffer to the specified size
    ///
    /// If the requested size is less than the current size, the last elements will be erased to fulfil the size
    /// requirement. If the requested size is more than the current size, default constructed elements will be inserted.
    /// \param newSize The requested new size
    void resize(const Size newSize) {
        if (newSize < size()) {
            erase(begin() + newSize, end());
        } else if (newSize > size()) {
            const Size deltaSize = newSize - size();
            reserve(newSize);
            for (Size i = 0; i < deltaSize; ++i) {
                mAllocator.construct(end(), std::move(ValueType()));
                ++mSize;
            }
        }
        ASSERT(size() == newSize);
    }

    /// Appends new element to the end of the buffer
    ///
    /// The element will be constructed using placement new expression. The arguments are forwarded using std::forward.
    /// \returns Reference to the inserted element
    template <typename... TArgs>
    Reference emplaceBack(TArgs&&... args) {
        reserve(size() + 1);
        mAllocator.construct(mData + size(), std::forward<TArgs>(args)...);
        ++mSize;
        return back();
    }

    /// Appends new element to the end of the buffer
    ///
    /// The element will be copy constructed from value
    /// \param value The value to append
    void push(ConstReference value) { emplaceBack(value); }

    /// Appends new element to the end of the buffer
    ///
    /// The value will be moved to the new element
    /// \param value The value to append
    void push(RValuetReference value = ValueType()) { emplaceBack(std::move(value)); }

    /// Inserts the elements specified by the iterator range to the given position
    /// \param position The position where to insert the elements
    /// \param first Iterator to the first element to be inserted
    /// \param last Iterator pointing right after the last element to be inserted. This means the last element within
    /// the range will not be inserted. \returns Iterator pointing to the first inserted element
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

    /// Inserts elements at the specified position
    /// \param position The position where to insert the elements
    /// \param value The value to be inserted
    /// \param count Tells how many times the value should be inserted
    /// \returns Iterator pointing to the first inserted element
    Iterator insert(const Iterator position, ConstReference value, const Size count = 1U) {
        const Size offset = position - begin();
        reserve(size() + count);
        const Iterator pos = begin() + offset;
        std::move_backward(pos, end(), end() + count);
        for (Size i = 0; i < count; ++i) {
            mAllocator.construct(pos + i, value);
        }
        mSize += count;
        return pos;
    }

    /// \copydoc insert(const Iterator position, ConstReference value, const Size count = 1U)
    Iterator insert(const Size position, ConstReference value, const Size count = 1U) {
        return insert(begin() + position, value, count);
    }

    /// Replaces the elements within the given iterator range
    ///
    /// \param first The beginning of the data to replace
    /// \pram last The end of the data to replace
    /// \param source The beginning of the data to replace the given range with
    Iterator replace(const Iterator first, const Iterator last, const ConstIterator source) {
        mAllocator.destroy(first, last);
        mAllocator.constructRange(first, last, source);
        return first;
    }

    /// Removes the last element
    ///
    /// Calling this function on an empty buffer is undefined
    void pop() {
        mAllocator.destroy(back());
        --mSize;
    }

    /// Inserts the elements from the given buffer at the end of this buffer
    /// \param b The buffer to be inserted
    /// \returns Reference to this object
    DynamicBuffer& operator+=(const DynamicBuffer& b) {
        reserve(size() + b.size());
        insert(end(), b.begin(), b.end());
        return *this;
    }

    /// Appends new element to the end of the buffer
    /// \param e The element to be inserted
    /// \returns Reference to this object
    DynamicBuffer& operator+=(ConstReference e) {
        push(e);
        return *this;
    }

    /// Returns a copy of this buffer with appended elements from the given buffer
    const DynamicBuffer operator+(const DynamicBuffer& rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    /// Returns a copy of this buffer with the given element appended
    const DynamicBuffer operator+(ConstReference rhs) const {
        DynamicBuffer sbb;
        sbb += *this;
        sbb += rhs;
        return sbb;
    }

    /// Returns a copy of this buffer with the given element prepended
    friend const DynamicBuffer operator+(ConstReference lhs, const DynamicBuffer& rhs) {
        DynamicBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    /// Returns whether or not the given buffer is equal to this buffer
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

    /// \copydoc bool operator==()
    bool operator!=(const DynamicBuffer& rhs) const { return !(*this == rhs); }

private:
    void allocateMemory(const Size size) {
        Pointer newData = mAllocator.allocate(size);
        std::move(begin(), end(), newData);
        if (mData) {
            mAllocator.destroy(begin(), end());
            mAllocator.deallocate(mData, 0);
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

NAMESPACE_CRYPTO_END

#endif // COMMON_BYTEBUFFER_H_
