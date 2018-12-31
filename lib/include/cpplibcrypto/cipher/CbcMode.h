#ifndef CPPLIBCRYPTO_CIPHER_CBCMODE_H_
#define CPPLIBCRYPTO_CIPHER_CBCMODE_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/cipher/CbcDecrypt.h"
#include "cpplibcrypto/cipher/CbcEncrypt.h"
#include "cpplibcrypto/common/Key.h"

NAMESPACE_CRYPTO_BEGIN

/// Convenience class for constructing block cipher encryptors/decryptors
///
/// For more details, see \ref CbcEncrypt and \ref CbcDecrypt
template <typename CipherT>
class CbcMode final {
public:
    using CipherType = CipherT;

    CbcMode() = default;

    struct Encryption {
        using CipherType = CipherT;

        Encryption(const Key& key, InitializationVector& iv)
            : mEncryptor(mCipher, key, iv) {}

        template <typename TBuffer>
        Size update(ConstByteBufferSlice input, TBuffer& output) {
            return mEncryptor.update(input, output);
        }

        template <typename TBuffer>
        void finalize(TBuffer& output, const Padding& padder) {
            mEncryptor.finalize(output, padder);
        }

        Size getBlockSize() const { return mCipher.getBlockSize(); }

    private:
        CipherT mCipher;
        CbcEncrypt mEncryptor;
    };

    struct Decryption {
        using CipherType = CipherT;

        Decryption(const Key& key, InitializationVector& iv)
            : mDecryptor(mCipher, key, iv) {}

        template <typename TBuffer>
        Size update(ConstByteBufferSlice input, TBuffer& output) {
            return mDecryptor.update(input, output);
        }

        template <typename TBuffer>
        void finalize(TBuffer& output, const Padding& padder) {
            mDecryptor.finalize(output, padder);
        }

        Size getBlockSize() const { return mCipher.getBlockSize(); }

    private:
        CipherT mCipher;
        CbcDecrypt mDecryptor;
    };
};

NAMESPACE_CRYPTO_END

#endif
