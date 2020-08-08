#ifndef CPPLIBCRYPTO_CIPHER_AES_H_
#define CPPLIBCRYPTO_CIPHER_AES_H_

#include "cpplibcrypto/cipher/BlockCipherSized.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/cipher/AesCore.h"
#include "cpplibcrypto/cipher/AesIv.h"
#include "cpplibcrypto/cipher/AesKey.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/common.h"

#include <memory>

NAMESPACE_CRYPTO_BEGIN

/// AES algorithm implementation in all common key sizes (128, 192, 256 bits)
class Aes : public BlockCipherSized<16> {
public:
    static constexpr Size Aes128 = 16;
    static constexpr Size Aes192 = 24;
    static constexpr Size Aes256 = 32;
    using Key = AesKey;
    using Iv = AesIv;

    Aes() = default;

    explicit Aes(const AesKey& key) { setKey(key); }

    Aes& operator=(Aes&& other) {
        mRoundKeys = std::move(other.mRoundKeys);
        return *this;
    }

    Aes(Aes&& other) { *this = std::move(other); }

    /// Encrypts one block
    ///
    /// Asserts the buffer size to be 16 bytes
    /// \param buffer The buffer which will get encrypted. Note that the buffer will be overwritten with the
    /// encrypted data.
    /// \throws Exception if \ref AesKey is not set
    void encryptBlock(ByteBufferSlice buffer) const override {
        ASSERT(buffer.size() == getBlockSize());
        processFirstRound(buffer);
        for (Byte i = 0; i < getNumberOfRounds() - 1; ++i) {
            processRound(buffer, i);
        }
        processLastRound(buffer);
    }

    /// Encrypts one block
    ///
    /// Asserts the buffer size to be 16 bytes
    /// \param buffer The buffer which will get decrypted. Note that the buffer will be overwritten with the
    /// decrypted data.
    /// \throws Exception if \ref AesKey is not set
    void decryptBlock(ByteBufferSlice buffer) const override {
        ASSERT(buffer.size() == getBlockSize());
        processFirstRoundInv(buffer);
        for (Byte i = getNumberOfRounds() - 1; i >= 1; --i) {
            processRoundInv(buffer, i);
        }
        processLastRoundInv(buffer);
    }

protected:
    void processFirstRound(ByteBufferSlice buffer) const { AesCore::addRoundKey(buffer, mRoundKeys, 0); }

    void processRound(ByteBufferSlice buffer, const Byte round) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::mixColumns(buffer);
        AesCore::addRoundKey(buffer, mRoundKeys, round + 1);
    }

    void processLastRound(ByteBufferSlice buffer) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::addRoundKey(buffer, mRoundKeys, getNumberOfRounds());
    }

    void processFirstRoundInv(ByteBufferSlice buffer) const {
        AesCore::addRoundKey(buffer, mRoundKeys, getNumberOfRounds());
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processRoundInv(ByteBufferSlice buffer, const Byte round) const {
        AesCore::addRoundKey(buffer, mRoundKeys, round);
        AesCore::mixColumnsInv(buffer);
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processLastRoundInv(ByteBufferSlice buffer) const { AesCore::addRoundKey(buffer, mRoundKeys, 0); }

    ByteBuffer mRoundKeys;

private:
    Aes& operator=(const Aes&) = delete;
    Aes(const Aes&) = delete;

    Byte getExpandedKeySize() const {
        switch (getKeySize()) {
        case Aes128:
            return 176;
        case Aes192:
            return 208;
        case Aes256:
            return 240;
        }
        throw Exception("AES: Key not set");
    }

    Byte getNumberOfRounds() const {
        switch (getKeySize()) {
        case Aes128:
            return 10;
        case Aes192:
            return 12;
        case Aes256:
            return 14;
        }
        throw Exception("AES: Key not set");
    }

    void keySchedule(const ConstByteBufferSlice& key) override {
        mRoundKeys.insert(mRoundKeys.end(), key.begin(), key.end());
        Byte rconIteration = 0;
        while (mRoundKeys.size() < getExpandedKeySize()) {
            StaticBuffer<Byte, 4> word32;
            word32.insert(word32.end(), mRoundKeys.end() - 4, mRoundKeys.end());

            if (mRoundKeys.size() % getKeySize() == 0) {
                AesCore::keyScheduleCore(word32, ++rconIteration);
            }

            if (getKeySize() == Aes256 && mRoundKeys.size() % getKeySize() == 16) {
                AesCore::subBytes(word32);
            }

            for (Byte i = 0; i < 4; ++i) {
                mRoundKeys << (mRoundKeys[mRoundKeys.size() - getKeySize()] ^ word32[i]);
            }
        }
    }
};

NAMESPACE_CRYPTO_END

#endif
