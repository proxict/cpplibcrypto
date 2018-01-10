#ifndef COMMON_BUFFERVIEW_H_
#define COMMON_BUFFERVIEW_H_

#include <iterator>

#include "common/LinearIterator.h"
#include "common/common.h"
#include "common/Memory.h"

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
    BufferView(TContainer& container)
    : mFirst(container.data()),
      mLast(container.data() + container.size()),
      mSize(container.size()),
      mCapacity(container.capacity()) {}

    BufferView(Pointer first, Pointer last)
    : mFirst(first),
      mLast(last),
      mSize(std::distance(first, last)),
      mCapacity(mSize) {}

    ConstReference at(const Size index) const { return *(mFirst + index); }

    Reference at(const Size index) { return *(mFirst + index); }

    ConstReference operator[](const Size index) const { return at(index); }

    Reference operator[](const Size index) { return at(index); }

    ConstReference back() const { return at(size() - 1); }

    Reference back() { return at(size() - 1); }

    ConstReference front() const { return at(0); }

    Reference front() { return at(0); }

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

} // namespace crypto

#endif
