cmake_minimum_required(VERSION 3.5.0)
project(ipv4 VERSION 1.0.0 LANGUAGES CXX)

#include(CTest)
#enable_testing()

add_library(ipv4 ipv4.cpp)

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)
