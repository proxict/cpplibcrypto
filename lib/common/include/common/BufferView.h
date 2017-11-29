#ifndef COMMON_BUFFERVIEW_H_
#define COMMON_BUFFERVIEW_H_

#include <iterator>

#include "common/common.h"

namespace crypto {

template <typename T>
class BufferView {
public:
    template <typename TContainer>
    BufferView(const TContainer& container) : mFirst(container.data()), mLast(container.data() + container.size()) {}

    template <typename TIterator>
    BufferView(const TIterator first, const TIterator last) : mFirst(first), mLast(last) {}

    const T* begin() const { return mFirst; }

    const T* end() const { return mLast; }

    Size size() const { return std::distance(mFirst, mLast); }

    const T& operator[](const Size index) const {
        return *(mFirst + index);
    }

    T& operator[](const Size index) {
        return *(mFirst + index);
    }

private:
    const T* mFirst;
    const T* mLast;
};

} // namespace crypto

#endif
