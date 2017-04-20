#ifndef CIPHER_AES_H_
#define CIPHER_AES_H_

#include "cipher/BlockCipherSized.h"

#include <memory>

#include "cipher/AesCore.h"
#include "common/ByteBuffer.h"
#include "common/common.h"
#include "common/Exception.h"
#include "common/KeyParams.h"

namespace crypto {

class AesKey : public KeyParams<16, 32, 8> {
public:
    AesKey() : KeyParams<16, 32, 8>() {}

    AesKey(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key = std::move(key);
    }

    AesKey(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key += key;
    }

    AesKey& operator=(AesKey&& other) {
        m_key = std::move(other.m_key);
        return *this;
    }

    AesKey(AesKey&& other) {
        *this = std::move(other);
    }

    std::size_t size() const override {
        return m_key.size();
    }

    const ByteBuffer& getKeyBytes() const override {
        return m_key;
    }

private:
    ByteBuffer m_key;
};

class Aes : public BlockCipherSized<16> {
public:
    static constexpr std::size_t Aes128 = 16;
    static constexpr std::size_t Aes192 = 24;
    static constexpr std::size_t Aes256 = 32;

    Aes() = default;

    explicit Aes(AesKey&& key) {
        setKey(std::move(key));
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
        return 0; // TODO(ProXicT): Throw exception
    }

    byte getNumberOfRounds() const {
        switch (getKeySize()) {
            case Aes128: return 10;
            case Aes192: return 12;
            case Aes256: return 14;
        }
        return 0; // TODO(ProXicT): Throw exception
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
