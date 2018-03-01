#ifndef FILEMANIP_UTILS_H_
#define FILEMANIP_UTILS_H_

#include "common/Exception.h"
#include "common/File.h"
#include "common/String.h"

NAMESPACE_CRYPTO_BEGIN
namespace utils {

/// Returns whether or not the file specified exists
inline bool fileExists(const String& filename) {
    try {
        File::open(filename, File::OpenMode::READ);
    } catch (const Exception& e) {
        return false;
    }
    return true;
}

/// Returns the size of the file specified
/// \throws Exception in case the file doesn't exist
inline Size getFileSize(const String& filename) {
    File f = File::open(filename, File::OpenMode::READ);
    f.seek(0, SeekPosition::END);
    return f.getPosition();
}

} // namespace utils
NAMESPACE_CRYPTO_END

#endif //FILEMANIP_UTILS_H_
