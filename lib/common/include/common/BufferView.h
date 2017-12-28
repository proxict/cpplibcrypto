#ifndef COMMON_BUFFERVIEW_H_
#define COMMON_BUFFERVIEW_H_

#include <iterator>

#include "common/LinearIterator.h"
#include "common/common.h"

namespace crypto {

template <typename T>
class BufferView {
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

    template <typename TContainer>
    BufferView(const TContainer& container)
    : mFirst(container.data()),
      mLast(container.data() + container.size()),
      mSize(container.size()),
      mCapacity(container.capacity()) {}

    ConstReference at(const Size index) const { return *(mFirst + index); }

    Reference at(const Size index) { return *(mFirst + index); }

    ConstReference operator[](const Size index) const { return at(index); }

    Reference operator[](const Size index) { return at(index); }

    ConstReference back() const { return at(size() - 1); }

    Reference back() { return at(size() - 1); }

    ConstPointer data() const { return mFirst; }

    Pointer data() { return mFirst; }

    Iterator begin() { return Iterator(data()); }

    Iterator end() { return Iterator(data(), size()); }

    ConstIterator begin() const { return cbegin(); }

    ConstIterator end() const { return cend(); }

    ConstIterator cbegin() const { return ConstIterator(data()); }

    ConstIterator cend() const { return ConstIterator(data(), size()); }

    bool empty() const { return size() == 0; }

    Size size() const { return mSize; }

    Size capacity() const { return mCapacity; }

private:
    const T* mFirst;
    const T* mLast;
    Size mSize;
    Size mCapacity;
};

} // namespace crypto

#endif
