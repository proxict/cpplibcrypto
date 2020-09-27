#ifndef CPPLIBCRYPTO_CIPHER_CBCMODE_H_
#define CPPLIBCRYPTO_CIPHER_CBCMODE_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/cipher/CbcDecrypt.h"
#include "cpplibcrypto/cipher/CbcEncrypt.h"
#include "cpplibcrypto/common/Key.h"

namespace crypto {

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

        template <typename TKey>
        Encryption(const TKey& key, const InitializationVector& iv)
            : mCipher(key)
            , mEncryptor(mCipher, iv) {}

        template <typename TBuffer>
        Size update(BufferSlice<const Byte> input, TBuffer& output) {
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

        template <typename TKey>
        Decryption(const TKey& key, const InitializationVector& iv)
            : mCipher(key)
            , mDecryptor(mCipher, iv) {}

        template <typename TBuffer>
        Size update(BufferSlice<const Byte> input, TBuffer& output) {
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

} // namespace crypto

#endif
