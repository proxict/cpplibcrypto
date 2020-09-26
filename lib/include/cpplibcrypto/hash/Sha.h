#ifndef CPPLIBCRYPTO_HASH_SHA_H_
#define CPPLIBCRYPTO_HASH_SHA_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/common/AnyOf.h"
#include "cpplibcrypto/common/Exception.h"

NAMESPACE_CRYPTO_BEGIN

enum class ShaFamily { SHA1, SHA224, SHA256, SHA384, SHA512 };

template <ShaFamily TFamily>
struct ShaState {
    using Word =
        Conditional<TFamily == anyOf(ShaFamily::SHA1, ShaFamily::SHA224, ShaFamily::SHA256), Dword, Qword>;

    static constexpr Size getBlockSize() {
        switch (TFamily) {
        case ShaFamily::SHA1:
            return 20;
        case ShaFamily::SHA224:
            [[fallthrough]];
        case ShaFamily::SHA256:
            return 32;
        case ShaFamily::SHA384:
            [[fallthrough]];
        case ShaFamily::SHA512:
            return 64;
        default:
            ASSERT(false);
            throw Exception("Invalid SHA family");
        }
    }

    StaticBuffer<Word, getBlockSize() / 4> H;

    ShaState() { reset(); }

    ShaState(ShaState&& other) { *this = std::move(other); }

    ShaState& operator=(ShaState&& other) {
        std::swap(H, other.H);
        return *this;
    }

    Word& operator[](const Size index) { return H[index]; }

    const Word& operator[](const Size index) const { return H[index]; }

    void reset() {
        H.clear();
        if constexpr (TFamily == ShaFamily::SHA1) {
            // Constants defined in FIPS 180-4, section 5.3.1
            H.push(0x67452301);
            H.push(0xEFCDAB89);
            H.push(0x98BADCFE);
            H.push(0x10325476);
            H.push(0xC3D2E1F0);
        } else if constexpr (TFamily == ShaFamily::SHA224) {
            // Constants defined in FIPS 180-4, section 5.3.2
            H.push(0xc1059ed8);
            H.push(0x367cd507);
            H.push(0x3070dd17);
            H.push(0xf70e5939);
            H.push(0xffc00b31);
            H.push(0x68581511);
            H.push(0x64f98fa7);
            H.push(0xbefa4fa4);
        } else if constexpr (TFamily == ShaFamily::SHA256) {
            // Constants defined in FIPS 180-4, section 5.3.3
            H.push(0x6A09E667);
            H.push(0xBB67AE85);
            H.push(0x3C6EF372);
            H.push(0xA54FF53A);
            H.push(0x510E527F);
            H.push(0x9B05688C);
            H.push(0x1F83D9AB);
            H.push(0x5BE0CD19);
        } else if constexpr (TFamily == ShaFamily::SHA384) {
            // Constants defined in FIPS 180-4, section 5.3.4
            H.push(0xcbbb9d5dc1059ed8ULL);
            H.push(0x629a292a367cd507ULL);
            H.push(0x9159015a3070dd17ULL);
            H.push(0x152fecd8f70e5939ULL);
            H.push(0x67332667ffc00b31ULL);
            H.push(0x8eb44a8768581511ULL);
            H.push(0xdb0c2e0d64f98fa7ULL);
            H.push(0x47b5481dbefa4fa4ULL);
        } else if constexpr (TFamily == ShaFamily::SHA512) {
            // Constants defined in FIPS 180-4, section 5.3.5
            H.push(0x6a09e667f3bcc908ULL);
            H.push(0xbb67ae8584caa73bULL);
            H.push(0x3c6ef372fe94f82bULL);
            H.push(0xa54ff53a5f1d36f1ULL);
            H.push(0x510e527fade682d1ULL);
            H.push(0x9b05688c2b3e6c1fULL);
            H.push(0x1f83d9abfb41bd6bULL);
            H.push(0x5be0cd19137e2179ULL);
        } else {
            throw Exception("Invalid SHA family");
        }
    }

private:
    ShaState(const ShaState&) = delete;
    ShaState& operator=(const ShaState&) = delete;
};

template <ShaFamily TFamily>
class Sha {
    static constexpr Size getDigestSize() {
        switch (TFamily) {
        case ShaFamily::SHA1:
            return 160 / 8;
        case ShaFamily::SHA224:
            return 224 / 8;
        case ShaFamily::SHA256:
            return 256 / 8;
        case ShaFamily::SHA384:
            return 384 / 8;
        case ShaFamily::SHA512:
            return 512 / 8;
        default:
            ASSERT(false);
            throw Exception("Invalid SHA family");
        }
    }

public:
    static constexpr Size BLOCK_SIZE = 64U;
    static constexpr Size DIGEST_SIZE = getDigestSize();

    using State = ShaState<TFamily>;

    Sha() { reset(); }

    virtual ~Sha() noexcept = default;

    Sha(Sha&& other) { *this = std::move(other); }

    Sha& operator=(Sha&& other) {
        std::swap(mState, other.mState);
        std::swap(mBlock, other.mBlock);
        std::swap(mTotalSize, other.mTotalSize);
        std::swap(mFinalized, other.mFinalized);
        return *this;
    }

    virtual void processBlock(BufferSlice<const Byte> in) = 0;

    /// Updates the state with the given data
    /// \throws Exception if the \ref finalize() has already been called or if the overall input size exceeded
    /// 2^64 bytes.
    template <typename TBuffer>
    void update(const TBuffer& in) {
        if (mFinalized) {
            throw Exception(
                "SHA: The state already has been computed. Reset the state to compute another digest.");
        }
        for (const Byte b : in) {
            mBlock.push(b);

            ++mTotalSize;
            // Overflowed
            if (mTotalSize == 0) {
                throw Exception("SHA: Input is too long");
            }

            if (mBlock.size() == BLOCK_SIZE) {
                processBlock(mBlock);
                mBlock.clear();
            }
        }
    }

    /// Finalizes the digest computation, outputs the result to the given buffer
    /// \param out Output buffer where the digest will be saved. Must be at least \ref Sha::DIGEST_SIZE long.
    /// \throws Exception if \ref finalize() has already been called
    template <typename TOut>
    void finalize(TOut& out) {
        if (mFinalized) {
            throw Exception(
                "SHA: The state already has been computed. Reset the state to compute another digest.");
        }
        padBlock();
        mTotalSize = 0;

        for (Size i = 0; i < DIGEST_SIZE; ++i) {
            out[i] = mState[i >> 2] >> 8 * (3 - (i & 0x03));
        }
        mFinalized = true;
    }

    State& getState() { return mState; }

    void setState(State state) { mState = std::move(state); }

    void reset() {
        mFinalized = false;
        mTotalSize = 0;
        mBlock.clear();
        mState.reset();
    }

protected:
    Sha(const Sha&) = delete;
    Sha& operator=(const Sha&) = delete;

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
        for (int i = 7; i >= 0; --i) {
            mBlock.push(totalBitsPtr[i]);
        }
        ASSERT(mBlock.size() == BLOCK_SIZE);
        processBlock(mBlock);
        mBlock.clear();
    }

    ShaState<TFamily> mState;
    StaticBuffer<Byte, BLOCK_SIZE> mBlock;
    Qword mTotalSize = 0;
    bool mFinalized = false;
};

NAMESPACE_CRYPTO_END

#endif // CPPLIBCRYPTO_HASH_SHA224_H_
