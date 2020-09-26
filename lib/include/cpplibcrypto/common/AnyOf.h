#ifndef CPPLIBCRYPTO_COMMON_ANYOF_H_
#define CPPLIBCRYPTO_COMMON_ANYOF_H_

#include "cpplibcrypto/common/utils.h"

#include <array>
#include <utility>

NAMESPACE_CRYPTO_BEGIN

template <typename T, int TSize>
struct AnyOfThis {
    template <typename TFirst, typename... TOthers>
    constexpr explicit AnyOfThis(TFirst&& first, TOthers&&... others)
        : values({ std::forward<TFirst>(first), std::forward<TOthers>(others)... }) {}

    std::array<T, TSize> values;
};

template <typename TFirst, typename... TOthers>
constexpr auto anyOf(TFirst&& first, TOthers&&... others) {
    constexpr std::size_t size = 1 + sizeof...(others);
    return AnyOfThis<typename std::decay<TFirst>::type, size>(std::forward<TFirst>(first),
                                                              std::forward<TOthers>(others)...);
}

template <typename T, int TSize>
constexpr bool operator==(const T value, const AnyOfThis<typename std::decay<T>::type, TSize>& anyOfThis) {
    return find(anyOfThis.values.begin(), anyOfThis.values.end(), value) != anyOfThis.values.end();
}
NAMESPACE_CRYPTO_END

#endif // COMMON_EXCEPTION_H_
