#ifndef CPPLIBCRYPTO_CIPHER_AESIV_H_
#define CPPLIBCRYPTO_CIPHER_AESIV_H_

#include "cpplibcrypto/common/InitializationVectorSized.h"

#include <memory>

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/common.h"

NAMESPACE_CRYPTO_BEGIN

/// Represents an initialization vector for AES
class AesIv : public InitializationVectorSized<16> {
public:
    /// \throws Exception if the IV size is not 16 bytes
    AesIv(ByteBuffer&& iv) {
        if (!isValid(iv.size())) {
            throw Exception("AES-IV: Invalid Initialization Vector size passed");
        }
        mIv = std::move(iv);
        mInitialIv += mIv;
    }

    /// \throws Exception if the IV size is not 16 bytes
    AesIv(const HexString& iv) {
        if (!isValid(iv.size())) {
            throw Exception("AES-IV: Invalid Initialization Vector size passed");
        }
        mIv += iv;
        mInitialIv += iv;
    }

    /// Returns the size of the key in bytes
    Size size() const override { return mIv.size(); }

    /// Sets the IV to the initial state
    void reset() override { mIv.replace(mIv.begin(), mIv.end(), mInitialIv.begin()); }

    /// Sets new IV
    void setNew(const ConstIterator begin) override { mIv.replace(mIv.begin(), mIv.end(), begin); }

    /// Returns a byte at the specified index
    ConstReference at(const Size index) const override { return mIv.at(index); }

    /// \copydoc at()
    ConstReference operator[](const Size index) const override { return mIv[index]; }

    /// Returns a pointer to the beginning of the IV byte sequence
    ConstPointer data() const override { return mIv.data(); }

private:
    ByteBuffer mIv;

    /// This will always store the initial IV so we are able to reset the IV in the future
    ByteBuffer mInitialIv;
};

NAMESPACE_CRYPTO_END

#endif
