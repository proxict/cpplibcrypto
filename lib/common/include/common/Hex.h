//------------------------------------------------------------------------------
///
/// \file
/// \brief Provides functions for converting base16 to base10 and vice versa
///
//------------------------------------------------------------------------------
#ifndef COMMON_HEX_H_
#define COMMON_HEX_H_

#include <sstream>
#include <string>

#include "common/ByteBuffer.h"

namespace crypto {

/**
 * \brief class responsible for converting base16 to base10 and vice versa
 */
class Hex {
public:
    /**
     * \brief encodes a ByteBuffer to base16
     * \param buf the ByteBuffer to encode
     * \return std::string with encoded data
     */
    template <typename TContainer>
    static std::string encode(const TContainer& buf);

    /**
     * \brief decodes a base16 string
     * \param hexStr the base16 string to decode
     * \return ByteBuffer with decoded data
     * \throws std::invalid_argument if hexStr contains invalid hexadecimal character
     */
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
