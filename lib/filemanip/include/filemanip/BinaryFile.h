#ifndef FILEMANIP_BINARYFILE_H_
#define FILEMANIP_BINARYFILE_H_

#include <fstream>
#include <string>

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/StaticBuffer.h"

namespace crypto {

/// Represents a binary file which can be read/written from/to a file system
class BinaryFile {
    using StaticByteBufferBase = StaticBufferBase<Byte>;

public:
    enum class Mode { Read = 1, Write };

    /// Opens the specified file in the specified mode
    /// \param filename The file to be opened
    /// \param mode The mode to open the file in
    BinaryFile(const std::string& filename, const Mode mode)
    : mStream(filename, (mode == Mode::Read ? std::ios::in : std::ios::out) | std::ios::binary), mMode(mode) {
        if (!mStream.good()) {
            throw Exception("Could not open the file specified");
        }
    }

    /// Reads the specified maximum number of bytes
    /// \param output Buffer to save the data to
    /// \param readMax The maximum number of bytes to read
    /// \returns The actual number of bytes read
    template <typename TBuffer>
    Size read(TBuffer& output, const Size readMax) {
        ASSERT(mMode == Mode::Read);
        ByteBuffer temp(readMax);
        mStream.read(reinterpret_cast<char*>(temp.data()), temp.size());
        const Size bytesRead = static_cast<Size>(mStream.gcount());

        output.reserve(bytesRead);
        output.insert(output.end(), temp.begin(), temp.begin() + bytesRead);

        return bytesRead;
    }

    /// Writes the buffer data
    /// \param buffer The buffer to be written
    /// \returns true if the data have been written successfully, false otherwise
    template <typename TBuffer>
    bool write(const TBuffer& buffer) {
        ASSERT(mMode == Mode::Write);
        return bool(mStream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

private:
    std::fstream mStream;
    Mode mMode;
};

} // namespace crypto

#endif
