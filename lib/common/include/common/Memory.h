#ifndef COMMON_MEMORY_H_
#define COMMON_MEMORY_H_

#include "common/TypeTraits.h"

namespace crypto {

template <typename T>
DisableIf<HasVirtualDestructor<T>::value> destroy(T& object) {
    object.T::~T();
}

template <typename T>
EnableIf<HasVirtualDestructor<T>::value> destroy(T& object) {
    object.~T();
}

template <typename TIterator>
void destroy(TIterator first, TIterator last) {
    for (auto it = first; it != last; ++it) {
        destroy(*it);
    }
}

} // namespace crypto

#endif

