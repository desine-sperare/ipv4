cmake_minimum_required(VERSION 3.5.0)

project(ipv4 VERSION 1.0.0 LANGUAGES CXX)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SOURCE_LIB ./src/ipv4.cpp)

#include(CTest)
#enable_testing()

add_library(ipv4 ${SOURCE_LIB})

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)
