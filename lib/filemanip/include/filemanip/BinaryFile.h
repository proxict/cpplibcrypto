#ifndef FILEMANIP_BINARYFILE_H_
#define FILEMANIP_BINARYFILE_H_

#include <fstream>
#include <string>

#include "common/Exception.h"
#include "common/StaticBuffer.h"
#include "common/DynamicBuffer.h"

namespace crypto {

/// Represents a binary file which can be read/written from/to a file system
class BinaryFile {
    using StaticByteBufferBase = StaticBufferBase<Byte>;
public:
    enum class Mode { Read = 1, Write };

    /// Opens the specified file in the specified mode
    /// \param filename The file to be opened
    /// \param mode The mode to open the file in
    BinaryFile(const std::string& filename, const Mode mode) :
        m_stream(filename, (mode == Mode::Read ? std::ios::in : std::ios::out) | std::ios::binary), m_mode(mode) {
        if (!m_stream.good()) {
            throw Exception("Could not open the file specified");
        }
    }

    /// Reads the specified maximum number of bytes
    /// \param output Buffer to save the data to
    /// \param readMax The maximum number of bytes to read
    /// \returns The actual number of bytes read
    template <typename TContainer>
    Size read(TContainer& output, const Size readMax) {
        ASSERT(m_mode == Mode::Read);
        ByteBuffer temp(readMax);
        m_stream.read(reinterpret_cast<char*>(temp.data()), temp.size());
        const Size bytesRead = static_cast<Size>(m_stream.gcount());

        output.reserve(bytesRead);
        output.insert(output.end(), temp.begin(), temp.begin() + bytesRead);

        return bytesRead;
    }

    /// Writes the buffer data
    /// \param buffer The buffer to be written
    /// \returns true if the data have been written successfully, false otherwise
    template <typename TContainer>
    bool write(const TContainer& buffer) {
        ASSERT(m_mode == Mode::Write);
        return bool(m_stream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

private:
    std::fstream m_stream;
    Mode m_mode;
};

} // namespace crypto

#endif

