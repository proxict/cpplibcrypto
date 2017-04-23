#ifndef CIPHER_CBCMODE_H_
#define CIPHER_CBCMODE_H_

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
        Encryption(const Key& key, InitializationVector& IV) : m_encryptor(m_cipher, key, IV) {}

        ByteBuffer update(const ByteBuffer& buffer) {
            return m_encryptor.update(buffer);
        }

    private:
        CipherT m_cipher;
        CbcEncrypt m_encryptor;
    };

    struct Decryption {
        Decryption(const Key& key, InitializationVector& IV) : m_decryptor(m_cipher, key, IV) {}

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
