#ifndef COMMON_BUFFERVIEW_H_
#define COMMON_BUFFERVIEW_H_

#include <iterator>

#include "common/LinearIterator.h"
#include "common/Memory.h"
#include "common/common.h"

NAMESPACE_CRYPTO_BEGIN

/// Provides a useful way to pass a pointer to a buffer of a known size
///
/// This view also allows to modify the elements.
template <typename T>
class BufferView final {
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

    /// Constructs the view from a container
    ///
    /// The container must have these function present:
    /// data(), size(), capacity()
    template <typename TBuffer>
    BufferView(TBuffer& container)
    : mFirst(container.data()),
      mLast(container.data() + container.size()),
      mSize(container.size()),
      mCapacity(container.capacity()) {}

    /// Constructs the view from an iterator range
    ///
    /// In this case the capacity always equal to the size which is the distance between the iterators
    /// \param first The beginning of the data to view
    /// \param last The end of the data to view
    BufferView(Pointer first, Pointer last)
    : mFirst(first), mLast(last), mSize(std::distance(first, last)), mCapacity(mSize) {}

    /// Returns a const reference to the element at the given index
    ConstReference at(const Size index) const { return *(mFirst + index); }

    /// Returns a reference to the element at the given index
    Reference at(const Size index) { return *(mFirst + index); }

    /// Returns a const reference to the element at the given index
    ConstReference operator[](const Size index) const { return at(index); }

    /// Returns a reference to the element at the given index
    Reference operator[](const Size index) { return at(index); }

    /// Returns a const reference to the last element
    ConstReference back() const { return at(size() - 1); }

    /// Returns a reference to the last element
    Reference back() { return at(size() - 1); }

    /// Returns a const reference to the first element
    ConstReference front() const { return at(0); }

    /// Returns a reference to the first element
    Reference front() { return at(0); }

    /// Returns a const pointer to the beginning
    ConstPointer data() const { return mFirst; }

    /// Returns a pointer to the beginning
    Pointer data() { return mFirst; }

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

    /// Returns whether or not the view is empty
    bool empty() const { return size() == 0; }

    /// Returns the size of the view
    Size size() const { return mSize; }

    /// In case the view was constructed from a container, returns the container capacity, in other cases returns the
    /// view size
    Size capacity() const { return mCapacity; }

    /// Replaces the elements within the given iterator range
    ///
    /// \param first The beginning of the data to replace
    /// \pram last The end of the data to replace
    /// \param with The beginning of the data to replace the given range with
    void replace(Iterator first, Iterator last, Iterator with) {
        memory::destroy(first, last);
        memory::constructRange<ValueType>(first, last, with);
    }

private:
    T* mFirst;
    T* mLast;
    Size mSize;
    Size mCapacity;
};

NAMESPACE_CRYPTO_END

#endif
