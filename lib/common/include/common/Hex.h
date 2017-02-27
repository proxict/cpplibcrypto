#ifndef COMMON_HEX_H_
#define COMMON_HEX_H_

#include <string>

#include "common/ByteBuffer.h"

namespace crypto {

class Hex {
public:
    static std::string encode(const ByteBuffer& buf);
    static ByteBuffer decode(const std::string& hexStr);

private:
    Hex() = delete;

    constexpr static byte hex2Byte(const char c);
};

} // namespace crypto

#endif
