#ifndef CPPLIBCRYPTO_IO_FILE_H_
#define CPPLIBCRYPTO_IO_FILE_H_

#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/common/Exception.h"

#include <cstdio>
#include <utility>

NAMESPACE_CRYPTO_BEGIN

enum class SeekPosition { BEGINNING, CURRENT, END };

/// RAII wrapper for FILE* and its operations. Non-copyable, movable.
/// Default-constructed and moved-from instances are considered closed, i.e. isOpen returns false
class File final {
public:
    enum class OpenMode { READ, WRITE, APPEND };

    File() = default;

    virtual ~File() noexcept { closeImpl(); }

    File(File&& other) noexcept
        : mFileName(std::move(other.mFileName))
        , mFile(other.mFile) {
        other.mFile = nullptr;
    }

    File& operator=(File&& other) noexcept {
        if (&other != this) {
            closeImpl();
            std::swap(mFileName, other.mFileName);
            std::swap(mFile, other.mFile);
        }
        return *this;
    }

    /// Closes the file
    void close() {
        ASSERT(isOpen());
        String fileName = std::move(mFileName); // save filename in case we need it for the exception below
        if (closeImpl() != 0) {
            throw Exception("Failed to close file (" + fileName + ')');
        }
    }

    /// Returns whether or not the file is open
    bool isOpen() const { return mFile != nullptr; }

    /// Returns the position in the current file
    Size getPosition() const {
        ASSERT(isOpen());
        return ftello(mFile);
    }

    /// Sets the current position in the file
    /// \param offset The offset from the specified position
    /// \param position The position origin
    /// \throws Exception if the file is not open and in case the seek fails
    void seek(const Size offset, const SeekPosition position) {
        ASSERT(isOpen());
        int whence = 0;
        switch (position) {
        case SeekPosition::BEGINNING:
            ASSERT(offset >= 0);
            whence = SEEK_SET;
            break;
        case SeekPosition::CURRENT:
            whence = SEEK_CUR;
            break;
        case SeekPosition::END:
            ASSERT(offset <= 0);
            whence = SEEK_END;
            break;
        default:
            ASSERT(false);
        }
        if (fseeko(mFile, offset, whence) != 0) {
            throw Exception("Could not seek in the file specified (" + mFileName + ')');
        }
    }

    Size read(void* output, const Size count) {
        ASSERT(isOpen());
        ASSERT(output != nullptr || count == 0);
        if (output == nullptr || count == 0) {
            return 0;
        }
        Size r = fread(output, 1, count, mFile);
        if (ferror(mFile)) {
            throw Exception("Error reading bytes from file (" + mFileName + ')');
        }
        return r;
    }

    void write(const void* source, const Size count) {
        ASSERT(isOpen());
        ASSERT(source != nullptr || count == 0);
        if (source == nullptr || count == 0) {
            return;
        }
        const auto written = fwrite(source, sizeof(char), count, mFile);
        if (written != count) {
            throw Exception("Could not write to the file specified");
        }
    }

    void flush() {
        ASSERT(isOpen());
        if (fflush(mFile) != 0) {
            throw Exception("Unable to flush file (" + mFileName + ')');
        }
    }

    bool eof() const {
        ASSERT(isOpen());
        return feof(mFile) != 0;
    }

    /// Opens a file in the given mode
    /// \param filename The path to the file to open
    /// \param mode The mode to open the file in. Could be either READ, WRITE or APPEND
    /// \throws Exception in case the file coudn't be open for any reason
    static File open(const String& fileName, const OpenMode mode) {
        FILE* file = fopen(fileName.c_str(), toFileOpenFlags(mode));
        if (!file) {
            throw Exception("Could not open the file specified (" + fileName + ')');
        }
        return File(std::move(fileName), file);
    }

    /// Returns whether or not the file specified exists
    static bool exists(const String& filename) {
        try {
            File::open(filename, File::OpenMode::READ);
        } catch (const Exception& e) {
            return false;
        }
        return true;
    }

    /// Returns the size of the file specified
    /// \throws Exception in case the file doesn't exist
    static Size getSize(const String& filename) {
        File f = File::open(filename, File::OpenMode::READ);
        f.seek(0, SeekPosition::END);
        return f.getPosition();
    }

private:
    File(String fileName, FILE* file)
        : mFileName(std::move(fileName))
        , mFile(file) {
        ASSERT(mFile != nullptr);
    }

    File(const File&) = delete;
    File& operator=(const File&) = delete;

    /// Closes the file
    int closeImpl() {
        if (mFile == nullptr) {
            return 0;
        }
        const int closeResult = fclose(mFile);
        mFile = nullptr;
        mFileName.clear();
        return closeResult;
    }

    static const char* toFileOpenFlags(const OpenMode mode) {
        switch (mode) {
        case OpenMode::READ:
            return "rb";
        case OpenMode::WRITE:
            return "wb";
        case OpenMode::APPEND:
            return "ab";
        default:
            ASSERT(false);
            return nullptr;
        }
    }

private:
    String mFileName;
    FILE* mFile = nullptr;
};

NAMESPACE_CRYPTO_END

#endif // COMMON_FILE_H_
