add_library(cipher_objects OBJECT
    src/Aes.cpp
)

target_include_directories(cipher_objects
    PUBLIC include
	PRIVATE ${common_includes}
)

get_property(cipher_includes_local TARGET cipher_objects PROPERTY INCLUDE_DIRECTORIES)
set(cipher_includes ${cipher_includes_local} CACHE STRING "Include directories for cipher module")

