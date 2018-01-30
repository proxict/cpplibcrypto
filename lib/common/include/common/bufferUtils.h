#ifndef COMMON_BUFFERUTILS_H_
#define COMMON_BUFFERUTILS_H_

#include "common/common.h"

namespace crypto {
namespace bufferUtils {

template <typename TContainer, typename TContainerXor>
inline void xorBuffer(TContainer& buffer, const TContainerXor& xorSource) {
    Size index = 0;
    for (typename TContainer::Reference b : buffer) {
        b ^= xorSource[index++];
    }
}

template <typename TIterator, typename TConstIterator>
inline void xorBuffer(TIterator first, TIterator last, const TConstIterator xorSourceFirst) {
    TIterator srcIt = xorSourceFirst;
    for (TIterator it = first; it != last; ++it, ++srcIt) {
        *it ^= *srcIt;
    }
}

template <typename TContainer, typename TIterator = typename TContainer::ConstIterator>
inline void pushXored(TContainer& container, const TIterator first, const TIterator last, const TIterator xorSource) {
    TIterator xorIt = xorSource;
    for (TIterator it = first; it != last; ++it) {
        container.push(*it ^ *xorIt++);
    }
}

} // namespace utils
} // namespace crypto

#endif

