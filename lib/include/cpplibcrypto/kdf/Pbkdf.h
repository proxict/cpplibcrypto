#ifndef CPPLIBCRYPTO_KDF_PBKDF_H_
#define CPPLIBCRYPTO_KDF_PBKDF_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/Password.h"
#include "cpplibcrypto/buffer/Salt.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/hash/Hmac.h"
#include "cpplibcrypto/hash/Sha1.h"

#include <algorithm>

namespace crypto {

/// RFC 2898 PBKDF2 implementation.
/// Derives key from a given password and salt. Non-copyable, moveable.
template <typename THash>
class Pbkdf {
    static constexpr Size DIGEST_SIZE = Hmac<THash>::DIGEST_SIZE;

public:
    Pbkdf() = default;

    Pbkdf(Password password, Salt salt)
        : mPassword(std::move(password))
        , mSalt(std::move(salt))
        , mKeySet(true) {
        mHmac.setKey(HmacKey(mPassword));
    }

    Pbkdf(Pbkdf&& other) { *this = std::move(other); }

    Pbkdf& operator=(Pbkdf&& other) {
        std::swap(mHmac, other.mHmac);
        std::swap(mPassword, other.mPassword);
        std::swap(mSalt, other.mSalt);
        std::swap(mKeySet, other.mKeySet);
        return *this;
    }

    /// Sets new password for the Pbkdf
    void setPassword(Password password) {
        mPassword = std::move(password);
        mHmac.setKey(HmacKey(mPassword));
        mKeySet = true;
    }

    /// Sets new salt for the Pbkdf
    void setSalt(Salt salt) { mSalt = std::move(salt); }

    /// Derives key from the given password and salt
    /// \param length Tells how long the derived key should be
    /// \param out The output buffer where the derived key will be stored. Must be at least as big as the
    /// requested length \param iterations The number of iterations which will be used to derive the key. More
    /// iterations usualy means more secure key.
    /// \throws Exception if the \ref Password is not set
    template <typename TOut>
    void derive(const Size length, TOut& out, const Size iterations) {
        if (!mKeySet) {
            throw Exception("PBKDF: Password not set");
        }
        StaticBuffer<Byte, DIGEST_SIZE> blockBuffer(DIGEST_SIZE);
        Size derived = 0;
        uint32_t count = 1;
        while (derived < length) {
            mHmac.update(mSalt);
            StaticBuffer<Byte, 4> countBytes(4);
            encodeBigEndian(countBytes, count++);
            mHmac.update(countBytes);
            mHmac.finalize(blockBuffer);

            StaticBuffer<Byte, DIGEST_SIZE> roundBuffer;
            roundBuffer << blockBuffer;
            constexpr Size s = DIGEST_SIZE;
            const Size blockSize = std::min(length - derived, s);
            for (Size c = 1; c < iterations; ++c) {
                mHmac.reset();
                mHmac.update(roundBuffer);
                mHmac.finalize(roundBuffer);
                for (Size i = 0; i < DIGEST_SIZE; ++i) {
                    blockBuffer[i] ^= roundBuffer[i];
                }
            }

            for (Size i = 0; i < blockSize; ++i) {
                out[derived + i] = blockBuffer[i];
            }
            mHmac.reset();
            derived += blockSize;
        }
        ASSERT(derived == length);
    }

private:
    template <typename TBuffer>
    static void encodeBigEndian(TBuffer& out, const uint32_t in) {
        out[0] = (in >> 24) & 0xff;
        out[1] = (in >> 16) & 0xff;
        out[2] = (in >> 8) & 0xff;
        out[3] = in & 0xff;
    }

    Pbkdf& operator=(const Pbkdf&) = delete;
    Pbkdf(const Pbkdf&) = delete;

    Hmac<THash> mHmac;
    Password mPassword;
    Salt mSalt;
    bool mKeySet = false;
};

using Pbkdf2 = Pbkdf<Sha1>;

} // namespace crypto

#endif // CPPLIBCRYPTO_KDF_PBKDF_H_
