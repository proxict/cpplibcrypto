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

    AesIV(ByteBuffer&& IV) {
        if (!isValid(IV.size())) {
            throw Exception("Invalid Initialization Vector size passed");
        }
        m_IV = std::move(IV);
        m_InitialIV += m_IV;
    }

    AesIV(const HexString& IV) {
        if (!isValid(IV.size())) {
            throw Exception("Invalid Initialization Vector size passed");
        }
        m_IV += IV;
        m_InitialIV += IV;
    }

    Size size() const override {
        return m_IV.size();
    }

    void reset() override {
        for (Size i = 0; i < m_IV.size(); ++i) {
            m_IV[i] = m_InitialIV[i];
        }
    }

    Byte operator[](const Size index) const override {
        return m_IV[index];
    }

    Byte& operator[](const Size index) override {
        return m_IV[index];
    }

    ByteBuffer m_IV;
    ByteBuffer m_InitialIV; // if we wanted to reset the IV
};

} // namespace crypto

#endif
