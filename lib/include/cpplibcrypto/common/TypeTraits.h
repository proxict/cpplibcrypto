#ifndef CPPLIBCRYPTO_COMMON_TYPETRAITS_H_
#define CPPLIBCRYPTO_COMMON_TYPETRAITS_H_

#include "cpplibcrypto/common/common.h"

#include <type_traits>

NAMESPACE_CRYPTO_BEGIN

template <bool TTest, typename TType = void>
using EnableIf = typename std::enable_if_t<TTest, TType>;

template <bool TTest, typename TType = void>
using DisableIf = EnableIf<!TTest, TType>;

template <typename T>
using IsConst = std::is_const<T>;

template <typename T>
using HasVirtualDestructor = std::has_virtual_destructor<T>;

template <bool TTest, typename TTrue, typename TFalse>
using Conditional = std::conditional_t<TTest, TTrue, TFalse>;

template <typename T>
using IsReference = std::is_reference<T>;

template <typename T>
using RemoveReference = std::remove_reference_t<T>;

template <typename T>
using ReferenceWrapper = std::reference_wrapper<T>;

template <typename T>
using ReferenceStorage =
    Conditional<IsReference<T>::value, ReferenceWrapper<RemoveReference<T>>, RemoveReference<T>>;

NAMESPACE_CRYPTO_END

#endif
