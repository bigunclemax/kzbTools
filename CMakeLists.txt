cmake_minimum_required(VERSION 3.17)
project(kzbTool)

set(CMAKE_CXX_STANDARD 20)

add_executable(kzbTool main.cpp)

if(WIN32)
    target_link_libraries(kzbTool ws2_32)
endif()