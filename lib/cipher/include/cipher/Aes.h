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
    static constexpr std::size_t Aes128 = 16;
    static constexpr std::size_t Aes192 = 24;
    static constexpr std::size_t Aes256 = 32;
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

    void encryptBlock(ByteBuffer& buffer) override {
        processFirstRound(buffer);
        for (byte i = 0; i < getNumberOfRounds() - 1; ++i) {
            processRound(buffer, i);
        }
        processLastRound(buffer);
    }

    void decryptBlock(ByteBuffer& buffer) override {
        processFirstRoundInv(buffer);
        for(byte i = getNumberOfRounds() - 1; i >= 1; --i) {
            processRoundInv(buffer, i);
        }
        processLastRoundInv(buffer);
    }

    byte getExpandedKeySize() const {
        switch (getKeySize()) {
            case Aes128: return 176;
            case Aes192: return 208;
            case Aes256: return 240;
        }
        throw Exception("Key not set");
    }

    byte getNumberOfRounds() const {
        switch (getKeySize()) {
            case Aes128: return 10;
            case Aes192: return 12;
            case Aes256: return 14;
        }
        throw Exception("Key not set");
    }

protected:
    void processFirstRound(ByteBuffer& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, 0);
    }

    void processRound(ByteBuffer& buffer, const byte round) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::mixColumns(buffer);
        AesCore::addRoundKey(buffer, m_roundKeys, round + 1);
    }

    void processLastRound(ByteBuffer& buffer) const {
        AesCore::subBytes(buffer);
        AesCore::shiftRows(buffer);
        AesCore::addRoundKey(buffer, m_roundKeys, getNumberOfRounds());
    }

    void processFirstRoundInv(ByteBuffer& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, getNumberOfRounds());
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processRoundInv(ByteBuffer& buffer, const byte round) const {
        AesCore::addRoundKey(buffer, m_roundKeys, round);
        AesCore::mixColumnsInv(buffer);
        AesCore::shiftRowsInv(buffer);
        AesCore::subBytesInv(buffer);
    }

    void processLastRoundInv(ByteBuffer& buffer) const {
        AesCore::addRoundKey(buffer, m_roundKeys, 0);
    }

protected:
    ByteBuffer m_roundKeys;

private:
    Aes& operator=(const Aes&) = delete;
    Aes(const Aes&) = delete;

    void keySchedule(const ByteBuffer& key) override {
        for (byte i = 0; i < getKeySize(); ++i) {
            m_roundKeys += key[i];
        }

        byte rconIteration = 0;
        while (m_roundKeys.size() < getExpandedKeySize()) {
            ByteBuffer word32;
            for (byte i = 0; i < 4; ++i) {
                word32 += m_roundKeys[i + m_roundKeys.size() - 4];
            }

            if (m_roundKeys.size() % getKeySize() == 0) {
                AesCore::keyScheduleCore(word32, ++rconIteration);
            }

            if (getKeySize() == Aes256 && m_roundKeys.size() % getKeySize() == 16) {
                AesCore::subBytes(word32);
            }

            for (byte i = 0; i < 4; ++i) {
                m_roundKeys += m_roundKeys[m_roundKeys.size() - getKeySize()] ^ word32[i];
            }
        }
    }
};

} // namespace crypto

#endif
