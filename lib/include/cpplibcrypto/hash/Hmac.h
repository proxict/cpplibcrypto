#ifndef CPPLIBCRYPTO_HASH_HMAC_H_
#define CPPLIBCRYPTO_HASH_HMAC_H_

// TODO(ProXicT): Move SA to common
#include "cpplibcrypto/cipher/SymmetricAlgorithm.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/common/KeySized.h"

NAMESPACE_CRYPTO_BEGIN

class HmacKey : public KeySized<0, std::numeric_limits<Size>::max()> {
public:
    HmacKey()
        : KeySized() {}

    HmacKey(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        mKey = std::move(key);
    }

    HmacKey(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        mKey += key;
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

template <typename THash>
class Hmac : public SymmetricAlgorithm {
public:
    static constexpr Size BLOCK_SIZE = 64U;
    static constexpr Size DIGEST_SIZE = THash::DIGEST_SIZE;

    Hmac() = default;

    Hmac(const HmacKey& key)
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

    void setKey(const HmacKey& key) {
        SymmetricAlgorithm::setKey(key);
        updateKey();
        mKeySet = true;
    }

    template <typename TBuffer>
    void update(const TBuffer& in) {
        if (!mKeySet) {
            throw Exception("Key not set");
        }
        mHasher.update(in);
    }

    template <typename TOut>
    void finalize(TOut& out) {
        ASSERT(mDerivedKey.size() == BLOCK_SIZE);
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
};

NAMESPACE_CRYPTO_END

#endif
