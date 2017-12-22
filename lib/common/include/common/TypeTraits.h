#ifndef COMMON_TYPETRAITS_H_
#define COMMON_TYPETRAITS_H_

#include <type_traits>

namespace crypto {

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

} // namespace crypto

#endif
