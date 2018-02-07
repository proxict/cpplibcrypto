#ifndef CIPHER_CBCMODE_H_
#define CIPHER_CBCMODE_H_

#include "cipher/CbcDecrypt.h"
#include "cipher/CbcEncrypt.h"
#include "common/BufferView.h"
#include "common/DynamicBuffer.h"
#include "common/Key.h"

namespace crypto {

using ByteBufferView = BufferView<Byte>;

/// Convenience class for constructing block cipher encryptors/decryptors
///
/// For more details, see \ref CbcEncrypt and \ref CbcDecrypt
template <typename CipherT>
class CbcMode {
    using StaticByteBufferBase = StaticBufferBase<Byte>;

public:
    using CipherType = CipherT;

    CbcMode() = default;

    struct Encryption {
        using CipherType = CipherT;

        Encryption(const Key& key, InitializationVector& iv) : mEncryptor(mCipher, key, iv) {}

        template <typename TBuffer>
        Size update(const ByteBufferView& input, TBuffer& output) {
            return mEncryptor.update(input, output);
        }

        template <typename TBuffer>
        void doFinal(const ByteBufferView& input, TBuffer& output, const Padding& padder) {
            mEncryptor.doFinal(input, output, padder);
        }

        Size getBlockSize() const { return mCipher.getBlockSize(); }

    private:
        CipherT mCipher;
        CbcEncrypt mEncryptor;
    };

    struct Decryption {
        using CipherType = CipherT;

        Decryption(const Key& key, InitializationVector& iv) : mDecryptor(mCipher, key, iv) {}

        template <typename TBuffer>
        Size update(const ByteBufferView& input, TBuffer& output) {
            return mDecryptor.update(input, output);
        }

        template <typename TBuffer>
        void doFinal(const ByteBufferView& input, TBuffer& output, const Padding& padder) {
            mDecryptor.doFinal(input, output, padder);
        }

        Size getBlockSize() const { return mCipher.getBlockSize(); }

    private:
        CipherT mCipher;
        CbcDecrypt mDecryptor;
    };
};

} // namespace crypto

#endif
