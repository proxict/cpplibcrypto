#ifndef CPPLIBCRYPTO_COMMON_UTILS_H_
#define CPPLIBCRYPTO_COMMON_UTILS_H_

#include "cpplibcrypto/common/TypeTraits.h"

namespace crypto {

template <typename TIterator, typename T, typename = DisableIf<__cplusplus >= 202002L>>
constexpr TIterator find(const TIterator first, const TIterator last, const T& value) {
    for (TIterator walk = first; walk != last; ++walk) {
        if (*walk == value) {
            return walk;
        }
    }
    return last;
}

} // namespace crypto

#endif // CPPLIBCRYPTO_COMMON_UTILS_H_
