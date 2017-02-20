//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines a sample function.
///
//------------------------------------------------------------------------------
#ifndef COMMON_SQUARE_H_
#define COMMON_SQUARE_H_

namespace crypto {

/**
 * \brief An exception thrown when a function is passed an illegal argument.
 */
class IllegalArgumentException {
};

/**
 * \brief Calculates the square of a given number.
 * \param x the number to square
 * \return the square of \c x
 * \throws IllegalArgumentException if the square of x does not fit to an \c int
 */
int square(int x);

} // namespace crypto

#endif // COMMON_SQUARE_H_
