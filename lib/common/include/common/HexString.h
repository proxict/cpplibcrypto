//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines a class reprezenation of base16 string
///
//------------------------------------------------------------------------------
#ifndef COMMON_HEX_STRING_H_
#define COMMON_HEX_STRING_H_

#include "common/ByteBuffer.h"
#include "common/Hex.h"

namespace crypto {

/**
 * \brief class reprezenation of base16 string
 */
class HexString {
public:
    /**
     * \brief HexString constructor
     * \param hexStr hexadecimal string
     * \throws std::invalid_argument if hexStr contains invalid hexadecimal character
     */
    HexString(const std::string& hexStr) : m_decoded(Hex::decode(hexStr)) {}

    /**
     * \brief operator= move assignment operator
     * \param other HexString instance
     * \return HexString object
     */
    HexString& operator=(HexString&& other) noexcept {
        m_decoded = std::move(other.m_decoded);
        return *this;
    }

    /**
     * \brief HexString move constructor
     * \param other HexString instance
     */
    HexString(HexString&& other) noexcept {
        *this = std::move(other);
    }

    /**
     * \brief operator+= append operator
     * \param rhs HexString object
     * \return HexString object
     */
    HexString& operator+=(const HexString& rhs) {
        m_decoded += rhs.m_decoded;
        return *this;
    }

    /**
     * \brief operator+= append HexString to ByteBuffer
     * \param lhs ByteBuffer instance
     * \param rhs HexString instance
     * \return ByteBuffer object
     */
    friend ByteBuffer& operator+=(ByteBuffer& lhs, const HexString& rhs) {
        lhs += rhs.m_decoded;
        return lhs;
    }

    /**
     * \brief operator+ adding two HexStrings
     * \param rhs HexString instance
     * \return HexString object
     */
    const HexString operator+(const HexString& rhs) const {
        HexString hexString("");
        hexString += *this;
        hexString += rhs;
        return hexString;
    }

    /**
     * \brief operator== compares if two HexStrings are equal
     * \param rhs HexString object
     * \return true if HexStrings are equal, false otherwise
     */
    bool operator==(const HexString& rhs) const {
        return m_decoded == rhs.m_decoded;
    }

private:
    HexString() = delete;
    HexString(const HexString&) = delete;
    HexString& operator=(const HexString&) = delete;

    ByteBuffer m_decoded;
};

} // namespace crypto

#endif
