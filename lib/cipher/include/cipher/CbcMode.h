#ifndef CIPHER_CBCMODE_H_
#define CIPHER_CBCMODE_H_

#include "cipher/CbcDecrypt.h"
#include "cipher/CbcEncrypt.h"
#include "common/ByteBuffer.h"
#include "common/Key.h"
#include "common/BufferView.h"

namespace crypto {

using ByteBufferView = BufferView<byte>;

template <typename CipherT>
class CbcMode {
public:
    using CipherType = CipherT;

    CbcMode() = default;

    struct Encryption {
        using CipherType = CipherT;

        Encryption(const Key& key, InitializationVector& IV) : m_encryptor(m_cipher, key, IV) {}

        std::size_t update(const ByteBufferView& input, StaticByteBufferBase& output) {
            return m_encryptor.update(input, output);
        }

        void doFinal(const ByteBufferView& input, StaticByteBufferBase& output) {
             m_encryptor.doFinal(input, output);
        }

        std::size_t getBlockSize() const {
            return m_cipher.getBlockSize();
        }

    private:
        CipherT m_cipher;
        CbcEncrypt m_encryptor;
    };

    struct Decryption {
        using CipherType = CipherT;

        Decryption(const Key& key, InitializationVector& IV) : m_decryptor(m_cipher, key, IV) {}

        std::size_t update(const ByteBufferView& input, StaticByteBufferBase& output) {
            return m_decryptor.update(input, output);
        }

        void doFinal(const ByteBufferView& input, StaticByteBufferBase& output) {
             m_decryptor.doFinal(input, output);
        }

        std::size_t getBlockSize() const {
            return m_cipher.getBlockSize();
        }

    private:
        CipherT m_cipher;
        CbcDecrypt m_decryptor;
    };
};

} // namespace crypto

#endif
