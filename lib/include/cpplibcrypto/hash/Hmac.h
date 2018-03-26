#ifndef CPPLIBCRYPTO_HASH_HMAC_H_
#define CPPLIBCRYPTO_HASH_HMAC_H_

#include "cpplibcrypto/common/SymmetricAlgorithm.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/buffer/Password.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/KeySized.h"

NAMESPACE_CRYPTO_BEGIN

/// Key for HMAC. Non-copyable, movable.
class HmacKey : public KeySized<0, std::numeric_limits<Size>::max()> {
public:
    HmacKey() = default;

    HmacKey(ByteBuffer&& key) {
        ASSERT(isValid(key.size()));
        mKey = std::move(key);
    }

    HmacKey(const HexString& key) {
        ASSERT(isValid(key.size()));
        mKey << key;
    }

    HmacKey(const Password& password) {
        ASSERT(isValid(password.size()));
        mKey.insert(mKey.end(), password.begin(), password.end());
    }

    HmacKey& operator=(HmacKey&& other) {
        std::swap(mKey, other.mKey);
        return *this;
    }

    HmacKey(HmacKey&& other) { mKey = std::move(other.mKey); }

    /// Returns the key size in bytes
    Size size() const override { return mKey.size(); }

    /// Returns the byte representation of the key
    const ByteBuffer& getBytes() const override { return mKey; }

private:
    HmacKey& operator=(const HmacKey&) = delete;
    HmacKey(const HmacKey&) = delete;

    ByteBuffer mKey;
};

/// RFC 2104 HMAC implementation.
/// Computes a digest based on the given underlying hashing algorithm.
template <typename THash>
class Hmac : public SymmetricAlgorithm {
public:
    static constexpr Size BLOCK_SIZE = 64U;
    static constexpr Size DIGEST_SIZE = THash::DIGEST_SIZE;

    Hmac() = default;

    explicit Hmac(const HmacKey& key)
        : Hmac() {
        setKey(key);
    }

    Hmac(Hmac&& other) { *this = std::move(other); }

    Hmac& operator=(Hmac&& other) {
        std::swap(mDerivedKey, other.mDerivedKey);
        std::swap(mHasher, other.mHasher);
        std::swap(mKeySet, other.mKeySet);
        return *this;
    }

    /// Sets new key for the HMAC.
    /// \throws Exception if \ref finalize() has already been called
    void setKey(const HmacKey& key) {
        if (mFinalized) {
            throw Exception(
                "HMAC: The digest already has been computed. Reset the state to compute another digest.");
        }
        SymmetricAlgorithm::setKey(key);
        updateKey();
        mKeySet = true;
    }

    /// Resets the state
    /// After calling this function, new digest can be computed using the same instance of this object
    void reset() {
        mHasher.reset();
        updateKey();
        mFinalized = false;
    }

    /// Updates the state with the given input
    /// \throws Exception in case the key has not been set or in case \ref finalize() has already been called
    template <typename TBuffer>
    void update(const TBuffer& in) {
        if (!mKeySet) {
            throw Exception("HMAC: Key not set");
        }
        if (mFinalized) {
            throw Exception(
                "HMAC: The digest already has been computed. Reset the state to compute another digest.");
        }
        mHasher.update(in);
    }

    /// Finalizes the digest computation, outputs the result to the given buffer
    /// \param out Output buffer where the digest will be saved. Must be at least \ref Hmac::DIGEST_SIZE long.
    /// \throws Exception if \ref finalize() has already been called
    template <typename TOut>
    void finalize(TOut& out) {
        ASSERT(mDerivedKey.size() == BLOCK_SIZE);
        if (mFinalized) {
            throw Exception(
                "HMAC: The digest already has been computed. Reset the state to compute another digest.");
        }
        StaticBuffer<Byte, DIGEST_SIZE> digest(DIGEST_SIZE);
        mHasher.finalize(digest);

        ByteBuffer oKeyPad;
        for (Size i = 0; i < BLOCK_SIZE; ++i) {
            oKeyPad.push(mDerivedKey[i] ^ 0x5c);
        }
        mHasher.reset();
        mHasher.update(oKeyPad);
        mHasher.update(digest);
        mHasher.finalize(out);
        mFinalized = true;
    }

private:
    Hmac& operator=(const Hmac&) = delete;
    Hmac(const Hmac&) = delete;

    void updateKey() {
        ASSERT(mDerivedKey.size() == BLOCK_SIZE);
        ByteBuffer iKeyPad;
        for (Size i = 0; i < BLOCK_SIZE; ++i) {
            iKeyPad.push(mDerivedKey[i] ^ 0x36);
        }
        mHasher.reset();
        mHasher.update(iKeyPad);
    }

    void keySchedule(const ConstByteBufferView& key) override {
        mDerivedKey.clear();
        if (key.size() > BLOCK_SIZE) {
            mHasher.reset();
            mHasher.update(key);
            ASSERT(DIGEST_SIZE <= BLOCK_SIZE);
            mDerivedKey.resize(DIGEST_SIZE);
            mHasher.finalize(mDerivedKey);
        } else {
            mDerivedKey.insert(mDerivedKey.end(), key.begin(), key.end());
        }
        mDerivedKey.insert(mDerivedKey.end(), 0x00, BLOCK_SIZE - mDerivedKey.size());
        ASSERT(mDerivedKey.size() == BLOCK_SIZE);
    }

    StaticBuffer<Byte, BLOCK_SIZE> mDerivedKey;
    THash mHasher;
    bool mKeySet = false;
    bool mFinalized = false;
};

NAMESPACE_CRYPTO_END

#endif
