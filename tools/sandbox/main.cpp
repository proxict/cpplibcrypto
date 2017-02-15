#include <iostream>
#include "common/Square.h"

static void printSquareOf(int i) {
    std::cout << "The square of "<<  i << " is " << crypto::square(i) << ".\n";
}

int main() {
    printSquareOf(5);
    return 0;
}
