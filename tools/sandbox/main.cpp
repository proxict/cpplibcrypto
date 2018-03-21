#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/cipher/Aes.h"
#include "cpplibcrypto/cipher/AesIv.h"
#include "cpplibcrypto/cipher/CbcMode.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/hash/Sha1.h"
#include "cpplibcrypto/hash/Md5.h"
#include "cpplibcrypto/io/Stream.h"
#include "cpplibcrypto/padding/Pkcs7.h"
#include "cpplibcrypto/hash/Hmac.h"

#include <iostream>

template <typename Encryptor>
void encFile(Encryptor& encryptor,
             const crypto::String& inputFileName,
             const crypto::String& outputFileName) {
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
void decFile(Decryptor& decryptor,
             const crypto::String& inputFileName,
             const crypto::String& outputFileName) {
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

void sha1digest(const crypto::String& inputFileName) {
    crypto::FileInputStream input(inputFileName);
    crypto::Sha1 sha1;
    while (!input.eof()) {
        crypto::StaticBuffer<crypto::Byte, 32> dataBuffer(32);
        const crypto::Size read = input.read(dataBuffer.data(), dataBuffer.capacity());
        dataBuffer.resize(read);
        sha1.update(dataBuffer);
    }
    crypto::StaticBuffer<crypto::Byte, 20> digest(20);
    sha1.finalize(digest);
    std::cout << crypto::Hex::encode(digest) << std::endl;
}

void md5digest(const crypto::String& inputFileName) {
    crypto::FileInputStream input(inputFileName);
    crypto::Md5 md5;
    while (!input.eof()) {
        crypto::StaticBuffer<crypto::Byte, 4096> dataBuffer(4096);
        const crypto::Size read = input.read(dataBuffer.data(), dataBuffer.capacity());
        dataBuffer.resize(read);
        md5.update(dataBuffer);
    }
    crypto::StaticBuffer<crypto::Byte, 16> digest(16);
    md5.finalize(digest);
    std::cout << crypto::Hex::encode(digest) << std::endl;
}

void hmacDigest() {
    crypto::Hmac<crypto::Sha1> hmac;
    hmac.setKey(crypto::ByteBuffer({'k', 'e', 'y'}));
    crypto::StaticBuffer<crypto::Byte, crypto::Sha1::DIGEST_SIZE> digest(crypto::Sha1::DIGEST_SIZE);
    hmac.update(crypto::String("The quick brown fox jumps "));
    hmac.update(crypto::String("over the lazy dog"));
    hmac.finalize(digest);
    std::cout << crypto::Hex::encode(digest) << std::endl;
}

/// The entry point of the sandbox application
/// \returns Process exit code whete \c 0 means success
int main() {
    try {
        sha1digest("CMakeCache.txt");
        md5digest("CMakeCache.txt");
        hmacDigest();
        return 0;

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
