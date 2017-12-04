add_library(padding_objects OBJECT
    src/Pkcs7.cpp
)

target_include_directories(padding_objects
    PUBLIC include
	PRIVATE ${common_includes}
)

get_property(padding_includes_local TARGET padding_objects PROPERTY INCLUDE_DIRECTORIES)
set(padding_includes ${padding_includes_local} CACHE STRING "Include directories for padding module")

