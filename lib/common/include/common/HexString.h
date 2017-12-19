//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines a class reprezenation of base16 string
///
//------------------------------------------------------------------------------
#ifndef COMMON_HEX_STRING_H_
#define COMMON_HEX_STRING_H_

#include "common/ByteBuffer.h"
#include "common/StaticByteBuffer.h"
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
     * \brief size getter
     * \return number of bytes of the decoded buffer
     */
    Size size() const {
        return m_decoded.size();
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
     * \brief operator+= append HexString to StaticByteBuffer
     * \param lhs StaticByteBuffer instance
     * \param rhs HexString instance
     * \return StaticByteBuffer object
     */
    friend StaticByteBufferBase& operator+=(StaticByteBufferBase& lhs, const HexString& rhs) {
        for (const Byte b : rhs.m_decoded) {
            lhs.push(b);
        }
        return lhs;
    }

    /**
     * \brief operator == compares if ByteBuffer and HexString are equal
     * \param lhs ByteBuffer object
     * \param rhs HexString object
     * \return true if lhs is equal to rhs, false otherwise
     */
    friend bool operator==(const ByteBuffer& lhs, const HexString& rhs) {
        return lhs == rhs.m_decoded;
    }

    /**
     * \brief operator == compares if HexString and ByteBuffe are equal
     * \param lhs HexStringr object
     * \param rhs ByteBuffe object
     * \return true if lhs is equal to rhs, false otherwise
     */
    friend bool operator==(const HexString& lhs, const ByteBuffer& rhs) {
        return lhs.m_decoded == rhs;
    }

    /**
     * \brief operator == compares if StaticByteBuffer and HexString are equal
     * \param lhs StaticByteBuffer object
     * \param rhs HexString object
     * \return true if lhs is equal to rhs, false otherwise
     */
    friend bool operator==(const StaticByteBufferBase& lhs, const HexString& rhs) {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (Size i = 0; i < lhs.size(); ++i) {
            if (lhs[i] != rhs.m_decoded[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * \brief operator == compares if HexString and StaticByteBuffer are equal
     * \param lhs HexString object
     * \param rhs StaticByteBuffer object
     * \return true if lhs is equal to rhs, false otherwise
     */
    friend bool operator==(const HexString& lhs, const StaticByteBufferBase& rhs) {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (Size i = 0; i < lhs.size(); ++i) {
            if (lhs.m_decoded[i] != rhs[i]) {
                return false;
            }
        }
        return true;
    }

    // TODO(ProXicT): operator!=

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
