//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines the entry point of the sandbox application.
///
//------------------------------------------------------------------------------
#include <iostream>
#include "common/Square.h"

namespace {

static void printSquareOf(int i) {
    std::cout << "The square of "<<  i << " is " << crypto::square(i) << ".\n";
}

}

/**
 * \brief The entry point of the application.
 * \return process exit code, \c 0 meaning success
 */
int main() {
    printSquareOf(5);
    return 0;
}
