#ifndef CIPHER_AESIV_H_
#define CIPHER_AESIV_H_

#include "common/InitializationVectorSized.h"

#include <memory>

#include "common/DynamicBuffer.h"
#include "common/common.h"
#include "common/Exception.h"
#include "common/HexString.h"

namespace crypto {

class AesIV : public InitializationVectorSized<16> {
public:
    AesIV() : InitializationVectorSized() {}

    AesIV(ByteBuffer&& iv) {
        if (!isValid(iv.size())) {
            throw Exception("Invalid Initialization Vector size passed");
        }
        mIv = std::move(iv);
        mInitialIv += mIv;
    }

    AesIV(const HexString& iv) {
        if (!isValid(iv.size())) {
            throw Exception("Invalid Initialization Vector size passed");
        }
        mIv += iv;
        mInitialIv += iv;
    }

    Size size() const override {
        return mIv.size();
    }

    void reset() override {
        mIv.replace(mIv.begin(), mIv.end(), mInitialIv.begin());
    }

    void setNew(const ConstIterator begin) override {
        mIv.replace(mIv.begin(), mIv.end(), begin);
    }

    ConstReference at(const Size index) const override {
        return mIv.at(index);
    }

    ConstReference operator[](const Size index) const override {
        return mIv[index];
    }

    ConstPointer data() const override {
        return mIv.data();
    }

    ByteBuffer mIv;
    ByteBuffer mInitialIv; // if we wanted to reset the IV
};

} // namespace crypto

#endif
