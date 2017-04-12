#ifndef CIPHER_CBCMODE_H_
#define CIPHER_CBCMODE_H_

#include <memory>

#include "cipher/CbcDecrypt.h"
#include "cipher/CbcEncrypt.h"
#include "common/ByteBuffer.h"
#include "common/Key.h"

namespace crypto {

template <typename CipherT>
class CbcMode {
public:
    CbcMode() = default;
    struct Encryption {
        Encryption(Key&& key, ByteBuffer&& IV) : m_encryptor(m_cipher, std::move(key), std::move(IV)) {}

        ByteBuffer update(const ByteBuffer& buffer) {
            return m_encryptor.update(buffer);
        }

    private:
        CipherT m_cipher;
        CbcEncrypt m_encryptor;
    };

    struct Decryption {
        Decryption(Key&& key, ByteBuffer&& IV) : m_decryptor(m_cipher, std::move(key), std::move(IV)) {}

        ByteBuffer update(const ByteBuffer& buffer) {
            return m_decryptor.update(buffer);
        }

    private:
        CipherT m_cipher;
        CbcDecrypt m_decryptor;
    };
};

} // namespace crypto

#endif
