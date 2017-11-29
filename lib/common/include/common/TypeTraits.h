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

} // namespace crypto

#endif

