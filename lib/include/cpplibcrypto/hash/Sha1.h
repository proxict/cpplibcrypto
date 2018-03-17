#ifndef CPPLIBCRYPTO_HASH_SHA1_H_
#define CPPLIBCRYPTO_HASH_SHA1_H_

#include "cpplibcrypto/buffer/BufferView.h"
#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"

NAMESPACE_CRYPTO_BEGIN

// First algorithm from the SHA family - computing 20byte digest
class Sha1 final {
public:
    using Word = uint32_t;
    static constexpr Byte DIGEST_SIZE = 20U;
    static constexpr Byte BLOCK_SIZE = 64U;

    struct State {
        StaticBuffer<Word, DIGEST_SIZE / 4> H;

        State() { reset(); }

        State(State&& other) { *this = std::move(other); }

        State& operator=(State&& other) {
            std::swap(H, other.H);
            return *this;
        }

        void reset() {
            H.clear();
            H.push(0x67452301);
            H.push(0xEFCDAB89);
            H.push(0x98BADCFE);
            H.push(0x10325476);
            H.push(0xC3D2E1F0);
        }

    private:
        State(const State&) = delete;
        State& operator=(const State&) = delete;
    };

    Sha1() { reset(); }

    Sha1(Sha1&& other) { *this = std::move(other); }

    Sha1& operator=(Sha1&& other) {
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

    /// Updates the state using the given input
    /// \param in The input from which the digest will be computed
    template <typename TBuffer>
    void update(const TBuffer& in) {
        ASSERT(!mFinalized);
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

    /// Finishes the computing process
    /// \param out A memory block to which the digest will be saved. Must have at least 20 bytes in size.
    template <typename T>
    void finalize(T& out) {
        ASSERT(!mFinalized);
        padBlock();
        mTotalSize = 0;

        for (int i = 0; i < DIGEST_SIZE; ++i) {
            out[i] = mState.H[i >> 2] >> 8 * (3 - (i & 0x03));
        }
        mFinalized = true;
    }

    State& getState() { return mState; }

    void setState(State state) { mState = std::move(state); }

private:
    Sha1(const Sha1&) = delete;
    Sha1& operator=(const Sha1&) = delete;

    void processBlock(BufferView<Byte> in) {
        const StaticBuffer<Word, 4> K({ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 });
        StaticBuffer<Word, 80> W(80);
        Word A, B, C, D, E;

        for (int t = 0; t < 16; t++) {
            W[t] = in[t * 4] << 24;
            W[t] |= in[t * 4 + 1] << 16;
            W[t] |= in[t * 4 + 2] << 8;
            W[t] |= in[t * 4 + 3];
        }

        for (int t = 16; t < 80; t++) {
            W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        }

        A = mState.H[0];
        B = mState.H[1];
        C = mState.H[2];
        D = mState.H[3];
        E = mState.H[4];

        for (int t = 0; t < 20; t++) {
            const Word temp = rotateLeft(A, 5) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 20; t < 40; t++) {
            const Word temp = rotateLeft(A, 5) + (B ^ C ^ D) + E + W[t] + K[1];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 40; t < 60; t++) {
            const Word temp = rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 60; t < 80; t++) {
            const Word temp = rotateLeft(A, 5) + (B ^ C ^ D) + E + W[t] + K[3];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        mState.H[0] += A;
        mState.H[1] += B;
        mState.H[2] += C;
        mState.H[3] += D;
        mState.H[4] += E;
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
        const uint64_t totalBits = mTotalSize * 8;
        const Byte* totalBitsPtr = reinterpret_cast<const Byte*>(&totalBits);
        for (int i = 7; i >= 0; --i) {
            mBlock.push(totalBitsPtr[i]);
        }
        processBlock(mBlock);
        mBlock.clear();
    }

    static Word rotateLeft(const Word value, const Byte bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    State mState;
    StaticBuffer<Byte, BLOCK_SIZE> mBlock;
    Size mTotalSize = 0;
    bool mFinalized = false;
};

NAMESPACE_CRYPTO_END

#endif
