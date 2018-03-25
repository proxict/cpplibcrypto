#ifndef CPPLIBCRYPTO_HASH_MD5_H_
#define CPPLIBCRYPTO_HASH_MD5_H_

#include "cpplibcrypto/buffer/BufferView.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"

#include <cstring>

NAMESPACE_CRYPTO_BEGIN

/// MD5 hash algorithm implementation according to the RFC 1321 standard
/// Computes 16 byte digest
class Md5 final {
public:
    using Dword = uint32_t;
    using Qword = uint64_t;
    static constexpr Size DIGEST_SIZE = 16U;
    static constexpr Size BLOCK_SIZE = 64U;

    struct State {
        StaticBuffer<Dword, DIGEST_SIZE / 4> H;

        State() { reset(); }

        State(State&& other) { *this = std::move(other); }

        State& operator=(State&& other) {
            std::swap(H, other.H);
            return *this;
        }

        Dword& operator[](const Size index) { return H[index]; }

        const Dword& operator[](const Size index) const { return H[index]; }

        void reset() {
            H.clear();
            H.push(0x67452301);
            H.push(0xEFCDAB89);
            H.push(0x98BADCFE);
            H.push(0x10325476);
        }

    private:
        State(const State&) = delete;
        State& operator=(const State&) = delete;
    };

    Md5() { reset(); }

    Md5(Md5&& other) { *this = std::move(other); }

    Md5& operator=(Md5&& other) {
        std::swap(mState, other.mState);
        std::swap(mBlock, other.mBlock);
        std::swap(mTotalSize, other.mTotalSize);
        std::swap(mFinalized, other.mFinalized);
        return *this;
    }

    /// Resets the state to the default, making it ready to compute another digest
    void reset() {
        mFinalized = false;
        mTotalSize = 0;
        mBlock.clear();
        mState.reset();
    }

    template <typename TBuffer>
    void update(const TBuffer& in) {
        if (mFinalized) {
            throw Exception(
                "The state already has been computed. Reset the state to compute another digest.");
        }
        for (const Byte b : in) {
            mBlock.push(b);

            ++mTotalSize;
            // Overflowed
            if (mTotalSize == 0) {
                throw Exception("Input is too long");
            }

            if (mBlock.size() == BLOCK_SIZE) {
                processBlock(mBlock);
                mBlock.clear();
            }
        }
    }

    template <typename T>
    void finalize(T& out) {
        if (mFinalized) {
            throw Exception(
                "The state already has been computed. Reset the state to compute another digest.");
        }
        padBlock();
        mTotalSize = 0;

        encode(out, mState.H);
        mFinalized = true;
    }

private:
    Md5(const Md5&) = delete;
    Md5& operator=(const Md5&) = delete;

    void processBlock(BufferView<const Byte> in) {
        ASSERT(in.size() == BLOCK_SIZE);
        static const StaticBuffer<Dword, 64>
            constantsArray({ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
                             0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                             0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
                             0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                             0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
                             0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                             0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
                             0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                             0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
                             0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                             0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 });

        // Per round shift amounts
        static const StaticBuffer<Dword, 64> shiftsArray(
            { 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
              14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
              4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21 });

        Dword A, B, C, D, F;
        A = mState[0];
        B = mState[1];
        C = mState[2];
        D = mState[3];
        F = 0;

        StaticBuffer<Dword, 16> block(16);
        decode(block, in);

        Byte g = 0;
        for (unsigned int i = 0; i < 64; ++i) {
            if (i < 16) {
                F = (B & C) | ((~B) & D);
                g = i;
            } else if (i < 32) {
                F = (D & B) | ((~D) & C);
                g = (5 * i + 1) & 0xf;
            } else if (i < 48) {
                F = B ^ C ^ D;
                g = (3 * i + 5) & 0xf;
            } else {
                F = C ^ (B | (~D));
                g = (7 * i) & 0xf;
            }

            const Dword temp = D;
            D = C;
            C = B;
            B += rotateLeft(A + F + constantsArray[i] + block[g], shiftsArray[i]);
            A = temp;
        }

        mState[0] += A;
        mState[1] += B;
        mState[2] += C;
        mState[3] += D;
    }

    void padBlock() {
        ASSERT(mBlock.size() < BLOCK_SIZE);
        mBlock.push(0x80);
        if (mBlock.size() > 56U) {
            mBlock.insert(mBlock.end(), 0x00, BLOCK_SIZE - mBlock.size());
            ASSERT(mBlock.size() == BLOCK_SIZE);
            processBlock(mBlock);
            mBlock.clear();
        }
        mBlock.insert(mBlock.end(), 0x00, 56U - mBlock.size());
        ASSERT(mBlock.size() == 56U);

        const Qword totalBits = mTotalSize * 8;
        const Byte* totalBitsPtr = reinterpret_cast<const Byte*>(&totalBits);
        for (Byte i = 0; i < 8; ++i) {
            mBlock.push(totalBitsPtr[i]);
        }
        ASSERT(mBlock.size() == BLOCK_SIZE);
        processBlock(mBlock);
        mBlock.clear();
    }

    template <typename TBuffer>
    static void encode(TBuffer& out, BufferView<const Dword> in) {
        for (Size i = 0; i < in.size(); i++) {
            out[i << 2] = in[i] & 0xff;
            out[(i << 2) + 1] = (in[i] >> 8) & 0xff;
            out[(i << 2) + 2] = (in[i] >> 16) & 0xff;
            out[(i << 2) + 3] = (in[i] >> 24) & 0xff;
        }
    }

    template <typename TBuffer>
    static void decode(TBuffer& out, BufferView<const Byte> in) {
        static_assert(sizeof(typename TBuffer::ValueType) == sizeof(Dword),
                      "The output buffer elements must be 32 bit values");
        ASSERT(in.size() % 4 == 0);
        for (Byte i = 0; i < in.size(); i += 4) {
            out[i >> 2] = ((Dword)in[i]) | (((Dword)in[i + 1]) << 8) | (((Dword)in[i + 2]) << 16) |
                          (((Dword)in[i + 3]) << 24);
        }
    }

    static Dword rotateLeft(const Dword value, const Byte bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    State mState;
    StaticBuffer<Byte, BLOCK_SIZE> mBlock;
    Qword mTotalSize;
    bool mFinalized = false;
};

NAMESPACE_CRYPTO_END

#endif
