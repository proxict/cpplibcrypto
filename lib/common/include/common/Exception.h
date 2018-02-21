#ifndef COMMON_EXCEPTION_H_
#define COMMON_EXCEPTION_H_

#include "common/String.h"
#include "common/common.h"

NAMESPACE_CRYPTO_BEGIN

/// Object expected to be thrown
///
/// Holds an error message in string format. This message is being dynamically allocated which means this object is not
/// suitable for throwing in situations where memory allocation is failing due its low state
class Exception {
public:
    Exception(const String& str) : mStr(str) {}

    /// Returns a reference to the message telling what went wrong
    virtual const String& what() const throw() { return mStr; }

private:
    const String mStr;
};

NAMESPACE_CRYPTO_END

#endif
