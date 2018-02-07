//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines the entry point of the sandbox application.
///
//------------------------------------------------------------------------------
#include <fstream>
#include <iostream>
#include <string>

#include "cipher/Aes.h"
#include "cipher/AesIV.h"
#include "cipher/CbcMode.h"
#include "common/Exception.h"
#include "common/HexString.h"
#include "common/StaticBuffer.h"
#include "filemanip/BinaryFile.h"
#include "filemanip/utils.h"
#include "padding/Pkcs7.h"

template <typename Encryptor>
void encFile(Encryptor& encryptor, const std::string& inputFileName, const std::string& outputFileName) {
    crypto::BinaryFile input(inputFileName, crypto::BinaryFile::Mode::Read);
    crypto::BinaryFile output(outputFileName, crypto::BinaryFile::Mode::Write);
    //crypto::StaticBuffer<crypto::Byte, 32> plainBuffer;
    //crypto::StaticBuffer<crypto::Byte, 32> cipherBuffer;
    crypto::DynamicBuffer<crypto::Byte> plainBuffer;
    crypto::DynamicBuffer<crypto::Byte> cipherBuffer;

    // Read max of plainBuffer.capacity()
    while (input.read(plainBuffer, 8)) {
        // Encrypt max of plainBuffer.size(), save the encrypted bytes to cipherBuffer and remove the plain data, which
        // got encrypted, from the plainBuffer.
        const crypto::Size encrypted = encryptor.update(plainBuffer, cipherBuffer); // BufferView in the lower level???
        plainBuffer.erase(0U, encrypted);

        // Save max of cipherBuffer.size() to output and erase the saved data from the cipherBuffer
        output.write(cipherBuffer);
        cipherBuffer.clear();
    }

    // Apply padding to the remaining bytes if any and save the result into cipherBuffer
    encryptor.doFinal(plainBuffer, cipherBuffer, crypto::Pkcs7());
    // Write the last chunk to the output
    output.write(cipherBuffer);
}

template <typename Decryptor>
void decFile(Decryptor& decryptor, const std::string& inputFileName, const std::string& outputFileName) {
    crypto::BinaryFile input(inputFileName, crypto::BinaryFile::Mode::Read);
    crypto::BinaryFile output(outputFileName, crypto::BinaryFile::Mode::Write);
    crypto::StaticBuffer<crypto::Byte, 4096> cipherBuffer;
    crypto::StaticBuffer<crypto::Byte, 4096> plainBuffer;

    while (input.read(cipherBuffer, cipherBuffer.capacity() - cipherBuffer.size())) {
        const crypto::Size decrypted = decryptor.update(cipherBuffer, plainBuffer);
        cipherBuffer.erase(0U, decrypted);
        output.write(plainBuffer);
        plainBuffer.clear();
    }

    decryptor.doFinal(cipherBuffer, plainBuffer, crypto::Pkcs7());
    output.write(plainBuffer);
}

/// The entry point of the sandbox application
/// \returns Process exit code whete \c 0 means success
int main() {
    try {
        crypto::Aes::Key key(crypto::HexString("2b7e151628aed2a6abf7158809cf4f3c"));
        crypto::Aes::IV iv(crypto::HexString("000102030405060708090A0B0C0D0E0F"));

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
