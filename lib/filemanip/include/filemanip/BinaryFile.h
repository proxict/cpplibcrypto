#ifndef FILEMANIP_BINARYFILE_H_
#define FILEMANIP_BINARYFILE_H_

#include <fstream>
#include <string>

#include "common/Exception.h"
#include "common/StaticByteBuffer.h"

namespace crypto {

class BinaryFile {
public:
    enum class Mode { Read = 1, Write };
    BinaryFile(const std::string& filename, const Mode mode) :
        m_stream(filename, (mode == Mode::Read ? std::ios::in : std::ios::out) | std::ios::binary), m_mode(mode) {
        if (!m_stream.good()) {
            throw Exception("Could not open the file specified");
        }
    }

    bool read(StaticByteBufferBase& buffer) {
        ASSERT(m_mode == Mode::Read);
        ByteBuffer temp(buffer.capacity() - buffer.size());
        m_stream.read(reinterpret_cast<char*>(temp.data()), temp.size());
        for (std::streamsize i = 0; i < m_stream.gcount(); ++i) {
            buffer.push(temp[i]);
        }
        return m_stream.gcount() > 0;
    }

    bool write(const StaticByteBufferBase& buffer) {
        ASSERT(m_mode == Mode::Write);
        return bool(m_stream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

private:
    std::fstream m_stream;
    Mode m_mode;
};

} // namespace crypto

#endif

