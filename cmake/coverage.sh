#!/usr/bin/env bash

for file in $(find . -name '*gcno'); do
  if [ ! -e ${file%.*}.o ]; then 
    rm $file; 
  fi; 
done

find . -name '*gcda' -exec rm -rf {} +;
rm -rf coverage

lcov -c -i -d . -o initial-coverage.info
./bin/unittests
lcov -c -d . -o test-coverage.info
lcov -a initial-coverage.info -a test-coverage.info -o coverage.info
lcov -r coverage.info '/usr/*' -o coverage.info
lcov -r coverage.info '*/test/*' -o coverage.info
lcov -r coverage.info '*/googletest*/*' -o coverage.info
genhtml coverage.info -o coverage -s -p $1 --highlight --demangle-cpp
rm *coverage.info
