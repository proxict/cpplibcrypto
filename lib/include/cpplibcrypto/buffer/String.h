#ifndef CPPLIBCRYPTO_BUFFER_STRING_H_
#define CPPLIBCRYPTO_BUFFER_STRING_H_

#include "cpplibcrypto/common/common.h"
#include "cpplibcrypto/buffer/utils/SecureAllocator.h"

#include <string>

NAMESPACE_CRYPTO_BEGIN

using String = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

NAMESPACE_CRYPTO_END

#endif
