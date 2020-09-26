#ifndef CPPLIBCRYPTO_HASH_SHA2_H_
#define CPPLIBCRYPTO_HASH_SHA2_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/bitManip.h"
#include "cpplibcrypto/hash/Sha.h"

NAMESPACE_CRYPTO_BEGIN

template <ShaFamily TFamily>
class Sha2 final : public Sha<TFamily> {
public:
    Sha2() = default;

    Sha2(Sha2&& other) = default;
    Sha2& operator=(Sha2&& other) = default;

private:
    virtual void processBlock(BufferSlice<const Byte> in) override {
        // Constants defined in FIPS 180-4, section 4.2.2
        static const StaticBuffer<Dword, 64> K({ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                                                 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                                                 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                                                 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                                 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
                                                 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                                                 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                                                 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                                 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                                                 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                                                 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                                                 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                                 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 });

        StaticBuffer<Dword, 64> W(64);
        for (int t = 0; t < 16; t++) {
            W[t] = in[t * 4] << 24;
            W[t] |= in[t * 4 + 1] << 16;
            W[t] |= in[t * 4 + 2] << 8;
            W[t] |= in[t * 4 + 3];
        }

        for (int t = 16; t < 64; t++) {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        Dword A = this->mState[0];
        Dword B = this->mState[1];
        Dword C = this->mState[2];
        Dword D = this->mState[3];
        Dword E = this->mState[4];
        Dword F = this->mState[5];
        Dword G = this->mState[6];
        Dword H = this->mState[7];

        for (int t = 0; t < 64; t++) {
            Dword temp1 = H + bigSigma1(E) + choose(E, F, G) + K[t] + W[t];
            Dword temp2 = bigSigma0(A) + majority(A, B, C);
            H = G;
            G = F;
            F = E;
            E = D + temp1;
            D = C;
            C = B;
            B = A;
            A = temp1 + temp2;
        }

        this->mState[0] += A;
        this->mState[1] += B;
        this->mState[2] += C;
        this->mState[3] += D;
        this->mState[4] += E;
        this->mState[5] += F;
        this->mState[6] += G;
        this->mState[7] += H;
    }

    static constexpr Dword sigma0(const Dword v) {
        return bits::rotateRight(v, 7) ^ bits::rotateRight(v, 18) ^ (v >> 3);
    }

    static constexpr Dword sigma1(const Dword v) {
        return bits::rotateRight(v, 17) ^ bits::rotateRight(v, 19) ^ (v >> 10);
    }

    static constexpr Dword bigSigma0(const Dword v) {
        return bits::rotateRight(v, 2) ^ bits::rotateRight(v, 13) ^ bits::rotateRight(v, 22);
    }

    static constexpr Dword bigSigma1(const Dword v) {
        return bits::rotateRight(v, 6) ^ bits::rotateRight(v, 11) ^ bits::rotateRight(v, 25);
    }

    /// Basically like "x ? y : z" for each bit
    static constexpr Dword choose(const Dword x, const Dword y, const Dword z) { return (x & y) ^ (~x & z); }

    static constexpr Dword majority(const Dword x, const Dword y, const Dword z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
};

/// SHA224 224-bit hasing algorithm
///
/// Computes 28 bytes digest
using Sha224 = Sha2<ShaFamily::SHA224>;

/// SHA256 256-bit hasing algorithm
///
/// Computes 32 bytes digest
using Sha256 = Sha2<ShaFamily::SHA256>;

NAMESPACE_CRYPTO_END

#endif // CPPLIBCRYPTO_HASH_SHA224_H_
