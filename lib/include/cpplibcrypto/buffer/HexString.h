#ifndef CPPLIBCRYPTO_BUFFER_HEXSTRING_H_
#define CPPLIBCRYPTO_BUFFER_HEXSTRING_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"

namespace crypto {

/// Represents a base-16 string
class HexString final {
    using StaticByteBufferBase = StaticBufferBase<Byte>;

public:
    HexString() = default;

    /// \param hexStr Hexadecimal data in string representation
    /// \throws Exception if hexStr contains an invalid base-16 character
    HexString(const String& hexStr)
        : mDecoded(Hex::decode(hexStr)) {}

    HexString& operator=(HexString&& other) noexcept {
        std::swap(mDecoded, other.mDecoded);
        return *this;
    }

    HexString(HexString&& other) noexcept { *this = std::move(other); }

    /// Returns the number of bytes of the decoded data
    Size size() const { return mDecoded.size(); }

    /// Appends data from the given HexString to this HexString
    /// \returns Reference to this object
    HexString& operator<<(const HexString& rhs) {
        mDecoded << rhs.mDecoded;
        return *this;
    }

    /// Appends data from this HexString to the given \ref ByteBuffer
    friend ByteBuffer& operator<<(ByteBuffer& lhs, const HexString& rhs) {
        lhs << rhs.mDecoded;
        return lhs;
    }

    /// Appends data from this HexString to the given \ref StaticBuffer
    friend StaticByteBufferBase& operator<<(StaticByteBufferBase& lhs, const HexString& rhs) {
        lhs.insert(lhs.end(), rhs.mDecoded.begin(), rhs.mDecoded.end());
        return lhs;
    }

    /// Returns whether or not the two HexStrings are equal
    bool operator==(const HexString& rhs) const { return mDecoded == rhs.mDecoded; }

    /// Returns whether or not the given buffer is equal to the data from this HexString
    template <typename TBuffer>
    friend bool operator==(const TBuffer& lhs, const HexString& rhs) {
        return bufferUtils::equal(lhs, rhs.mDecoded);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator!=(const TBuffer& lhs, const HexString& rhs) {
        return !bufferUtils::equal(lhs, rhs.mDecoded);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator==(const HexString& lhs, const TBuffer& rhs) {
        return bufferUtils::equal(lhs.mDecoded, rhs);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator!=(const HexString& lhs, const TBuffer& rhs) {
        return !bufferUtils::equal(lhs.mDecoded, rhs);
    }

private:
    HexString(const HexString&) = delete;
    HexString& operator=(const HexString&) = delete;

    ByteBuffer mDecoded;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_BUFFER_HEXSTRING_H_
