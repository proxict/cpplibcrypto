#ifndef COMMON_MEMORY_H_
#define COMMON_MEMORY_H_

#include <utility>

#include "common/TypeTraits.h"
#include "common/common.h"

namespace crypto {
namespace memory {

    template <typename T>
    inline T* allocate(const Size count) {
        return static_cast<T*>(::operator new(count * sizeof(T)));
    }

    inline void deallocate(void* ptr) { ::operator delete(ptr); }

    template <typename T, typename... TArgs>
    inline void construct(void* ptr, TArgs&&... value) {
        new (ptr) T(std::forward<TArgs>(value)...);
    }

    template <typename T>
    inline void destroy(T& object) {
        object.~T();
    }

    template <typename TIterator>
    inline void destroy(TIterator first, TIterator last) {
        for (auto it = first; it != last; ++it) {
            destroy(*it);
        }
    }

} // namespace memory
} // namespace crypto

#endif
