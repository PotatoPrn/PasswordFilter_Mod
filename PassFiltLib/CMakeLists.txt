cmake_minimum_required(VERSION 3.28)
project(PassFiltLib)

set(CMAKE_CXX_STANDARD 17)


set(LIBRARY_OUTPUT_PATH "../../bin")

include_directories(Extern/zxcvbn-c)


add_library(${CMAKE_PROJECT_NAME} SHARED
        main.cpp
        Extern/zxcvbn-c/zxcvbn.cpp
        Utils.cpp


)


target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE USE_DICT_FILE)

# File Compilation
#target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "/NOENTRY")
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE "/GS-")