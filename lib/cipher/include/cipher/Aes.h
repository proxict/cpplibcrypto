#ifndef CIPHER_AES_H_
#define CIPHER_AES_H_

#include "cipher/BlockCipherSized.h"

#include <memory>

#include "cipher/AesCore.h"
#include "cipher/AesKey.h"
#include "cipher/AesIV.h"
#include "common/ByteBuffer.h"
#include "common/common.h"
#include "common/Exception.h"

namespace crypto {

class Aes : public BlockCipherSized<16> {
public:
    static constexpr Size Aes128 = 16;
    static constexpr Size Aes192 = 24;
    static constexpr Size Aes256 = 32;
    using Key = AesKey;
    using IV = AesIV;

    Aes() = default;

    explicit Aes(const AesKey& key) {
        setKey(key);
    }

    Aes& operator=(Aes&& other) {
        m_roundKeys = std::move(other.m_roundKeys);
        return *this;
    }

    Aes(Aes&& other) {
        *this = std::move(other);
    }

    virtual ~Aes() = default;

    void encryptBlock(StaticByteBufferBase& buffer) override {
        processFirstRound(buffer);
        for (Byte i = 0; i < getNumberOfRounds() - 1; ++i) {
            processRound(buffer, i);
        }
        processLastRound(buffer);
    }

    void decryptBlock(StaticByteBufferBase& buffer) override {
        processFirstRoundInv(buffer);
        for(Byte i = getNumberOfRounds() - 1; i >= 1; --i) {
            processRoundInv(buffer, i);
        }
        processLastRoundInv(buffer);
    }

    Byte getExpandedKeySize() const {
        switch (getKeySize()) {
            case Aes128: return 176;
            case Aes192: return 208;
            case Aes256: return 240;
        }
        throw Exception("Key not set");
    }

    Byte getNumberOfRounds() const {
        switch (getKeySize()) {
            case Aes128: return 10;
            case Aes192: return 12;
            case Aes256: return 14;
        }
        throw Exception("Key not set");
    }

protected:
    void processFirstRound(StaticByteBufferBase& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, 0);
    }

    void processRound(StaticByteBufferBase& buffer, const Byte round) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::mixColumns(buffer);
        AesCore::addRoundKey(buffer, m_roundKeys, round + 1);
    }

    void processLastRound(StaticByteBufferBase& buffer) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::addRoundKey(buffer, m_roundKeys, getNumberOfRounds());
    }

    void processFirstRoundInv(StaticByteBufferBase& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, getNumberOfRounds());
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processRoundInv(StaticByteBufferBase& buffer, const Byte round) const {
        AesCore::addRoundKey(buffer, m_roundKeys, round);
        AesCore::mixColumnsInv(buffer);
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processLastRoundInv(StaticByteBufferBase& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, 0);
    }

protected:
    ByteBuffer m_roundKeys;

private:
    Aes& operator=(const Aes&) = delete;
    Aes(const Aes&) = delete;

    void keySchedule(const ByteBuffer& key) override {
        for (Byte i = 0; i < getKeySize(); ++i) {
            m_roundKeys += key[i];
        }

        Byte rconIteration = 0;
        while (m_roundKeys.size() < getExpandedKeySize()) {
            StaticByteBuffer<4> word32;
            for (Byte i = 0; i < 4; ++i) {
                word32.push(m_roundKeys[i + m_roundKeys.size() - 4]);
            }

            if (m_roundKeys.size() % getKeySize() == 0) {
                AesCore::keyScheduleCore(word32, ++rconIteration);
            }

            if (getKeySize() == Aes256 && m_roundKeys.size() % getKeySize() == 16) {
                AesCore::subBytes(word32);
            }

            for (Byte i = 0; i < 4; ++i) {
                m_roundKeys += m_roundKeys[m_roundKeys.size() - getKeySize()] ^ word32[i];
            }
        }
    }
};

} // namespace crypto

#endif
