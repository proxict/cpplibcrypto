//------------------------------------------------------------------------------
///
/// \file
/// \brief Provides functions for converting base16 to base10 and vice versa
///
//------------------------------------------------------------------------------
#ifndef COMMON_HEX_H_
#define COMMON_HEX_H_

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
    static std::string encode(const ByteBuffer& buf);

    /**
     * \brief decodes a base16 string
     * \param hexStr the base16 string to decode
     * \return ByteBuffer with decoded data
     * \throws std::invalid_argument if hexStr contains invalid hexadecimal character
     */
    static ByteBuffer decode(const std::string& hexStr);

private:
    Hex() = delete;

    constexpr static byte hex2Byte(const char c);
};

} // namespace crypto

#endif
