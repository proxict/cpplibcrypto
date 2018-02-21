#include "cipher/Aes.h"
#include "cipher/AesIv.h"
#include "cipher/CbcMode.h"
#include "common/Exception.h"
#include "common/HexString.h"
#include "common/StaticBuffer.h"
#include "common/Stream.h"
#include "filemanip/utils.h"
#include "padding/Pkcs7.h"
#include "common/String.h"

#include <iostream>

template <typename Encryptor>
void encFile(Encryptor& encryptor, const crypto::String& inputFileName, const crypto::String& outputFileName) {
    crypto::FileInputStream input(inputFileName);
    crypto::FileOutputStream output(outputFileName);
    crypto::DynamicBuffer<crypto::Byte> cipherBuffer;

    while (!input.eof()) {
        crypto::StaticBuffer<crypto::Byte, 4096> plainBuffer(4096);
        const crypto::Size read = input.read(plainBuffer.data(), plainBuffer.size());
        plainBuffer.resize(read);
        encryptor.update(plainBuffer, cipherBuffer);
        output.write(cipherBuffer.data(), cipherBuffer.size());
        cipherBuffer.clear();
    }

    encryptor.finalize(cipherBuffer, crypto::Pkcs7());
    output.write(cipherBuffer.data(), cipherBuffer.size());
}

template <typename Decryptor>
void decFile(Decryptor& decryptor, const crypto::String& inputFileName, const crypto::String& outputFileName) {
    crypto::FileInputStream input(inputFileName);
    crypto::FileOutputStream output(outputFileName);
    crypto::DynamicBuffer<crypto::Byte> plainBuffer;

    while (!input.eof()) {
        crypto::StaticBuffer<crypto::Byte, 4096> cipherBuffer(4096);
        const crypto::Size read = input.read(cipherBuffer.data(), cipherBuffer.capacity());
        cipherBuffer.resize(read);
        decryptor.update(cipherBuffer, plainBuffer);
        output.write(plainBuffer.data(), plainBuffer.size());
        plainBuffer.clear();
    }

    decryptor.finalize(plainBuffer, crypto::Pkcs7());
    output.write(plainBuffer.data(), plainBuffer.size());
}

/// The entry point of the sandbox application
/// \returns Process exit code whete \c 0 means success
int main() {
    try {
        crypto::Aes::Key key(crypto::HexString("2b7e151628aed2a6abf7158809cf4f3c"));
        crypto::Aes::Iv iv(crypto::HexString("000102030405060708090A0B0C0D0E0F"));

        crypto::CbcMode<crypto::Aes>::Encryption enc(key, iv);
        encFile(enc, "CMakeCache.txt", "cipher");

        iv.reset();
        crypto::CbcMode<crypto::Aes>::Decryption dec(key, iv);
        decFile(dec, "cipher", "plainOut");
    } catch (const crypto::Exception& e) {
        std::cout << e.what() << '\n';
        return 1;
    }
    return 0;
}
