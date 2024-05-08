cmake_minimum_required(VERSION 3.28)
project(PassFiltLib)

set(CMAKE_CXX_STANDARD 11)

set(LIBRARY_OUTPUT_PATH "../../bin")

include_directories(Extern/zxcppvbn)

set(ZXCVBN
        Extern/zxcppvbn/adjacency_graphs.cpp
        Extern/zxcppvbn/frequency_lists.cpp
        Extern/zxcppvbn/init.cpp
        Extern/zxcppvbn/matching.cpp
        Extern/zxcppvbn/scoring.cpp

        Extern/zxcppvbn/tools/tinf/adler32.c
        Extern/zxcppvbn/tools/tinf/crc32.c
        Extern/zxcppvbn/tools/tinf/tinfgzip.c
        Extern/zxcppvbn/tools/tinf/tinflate.c
        Extern/zxcppvbn/tools/tinf/tinfzlib.c

)

add_library(${CMAKE_PROJECT_NAME} SHARED
        main.cpp
        Utils.cpp
        ${ZXCVBN}

)


# File Compilation
#target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "/NOENTRY")
#target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE "/GS-")