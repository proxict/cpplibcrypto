#ifndef CPPLIBCRYPTO_HASH_SHA1_H_
#define CPPLIBCRYPTO_HASH_SHA1_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/bitManip.h"
#include "cpplibcrypto/hash/Sha.h"

NAMESPACE_CRYPTO_BEGIN

/// SHA1 160-bit hasing algorithm
///
/// Computes 20 bytes digest
class Sha1 final : public Sha<ShaFamily::SHA1> {
public:
    Sha1() = default;

    Sha1(Sha1&& other) = default;
    Sha1& operator=(Sha1&& other) = default;

private:
    Sha1(const Sha1&) = delete;
    Sha1& operator=(const Sha1&) = delete;

    virtual void processBlock(BufferSlice<const Byte> in) override {
        // Constants defined in FIPS 181-4, section 4.2.1
        static const StaticBuffer<Dword, 4> K({ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 });

        StaticBuffer<Dword, 80> W(80);
        for (int t = 0; t < 16; t++) {
            W[t] = in[t * 4] << 24;
            W[t] |= in[t * 4 + 1] << 16;
            W[t] |= in[t * 4 + 2] << 8;
            W[t] |= in[t * 4 + 3];
        }

        for (int t = 16; t < 80; t++) {
            W[t] = bits::rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        }

        Dword A = mState[0];
        Dword B = mState[1];
        Dword C = mState[2];
        Dword D = mState[3];
        Dword E = mState[4];

        for (int t = 0; t < 20; t++) {
            const Dword temp = bits::rotateLeft(A, 5) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
            E = D;
            D = C;
            C = bits::rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 20; t < 40; t++) {
            const Dword temp = bits::rotateLeft(A, 5) + (B ^ C ^ D) + E + W[t] + K[1];
            E = D;
            D = C;
            C = bits::rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 40; t < 60; t++) {
            const Dword temp = bits::rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
            E = D;
            D = C;
            C = bits::rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 60; t < 80; t++) {
            const Dword temp = bits::rotateLeft(A, 5) + (B ^ C ^ D) + E + W[t] + K[3];
            E = D;
            D = C;
            C = bits::rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        mState[0] += A;
        mState[1] += B;
        mState[2] += C;
        mState[3] += D;
        mState[4] += E;
    }
};

NAMESPACE_CRYPTO_END

#endif
