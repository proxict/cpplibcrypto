#ifndef COMMON_HEX_H_
#define COMMON_HEX_H_

#include <sstream>
#include <string>

#include "common/DynamicBuffer.h"

namespace crypto {

/// Converted from base-16 to base-10 and vice versa
class Hex {
public:
    /// Encodes the given buffer to base-16
    /// \returns string representation of the encoded data
    template <typename TContainer>
    static std::string encode(const TContainer& buf);

    /// Decodes the given base-16 string
    /// \returns base-10 buffer of bytes
    /// \throws Exception if hexStr contains an invalid base-16 character
    static ByteBuffer decode(const std::string& hexStr);

private:
    Hex() = delete;

    constexpr static Byte hex2Byte(const char c);
};

template <typename TContainer>
std::string Hex::encode(const TContainer& buf) {
    constexpr static const char* lookupTable = "0123456789abcdef";
    std::ostringstream bytes;
    for (const Byte b : buf) {
        bytes << lookupTable[b >> 4] << lookupTable[b & 0x0f];
    }
    return bytes.str();
}

} // namespace crypto

#endif
