cmake_minimum_required(VERSION 3.28)
project(PassFiltLib)

set(CMAKE_CXX_STANDARD 14)


set(LIBRARY_OUTPUT_PATH "../../bin")

include_directories(Extern/zxcvbn-cpp/native-src)
file(GLOB_RECURSE SOURCES "Extern/zxcvbn-cpp/native-src/zxcvbn/*.cpp")

add_library(${CMAKE_PROJECT_NAME} SHARED
        ${SOURCES}
        main.cpp
        Utils.cpp


)
# File Compilation
#target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "/NOENTRY")
#target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE "/GS-")