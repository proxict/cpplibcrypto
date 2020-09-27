#ifndef CPPLIBCRYPTO_BUFFER_STRING_H_
#define CPPLIBCRYPTO_BUFFER_STRING_H_

#include "cpplibcrypto/buffer/utils/SecureAllocator.h"
#include "cpplibcrypto/common/common.h"

#include <string>

namespace crypto {

using String = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

} // namespace crypto

#endif // CPPLIBCRYPTO_BUFFER_STRING_H_
