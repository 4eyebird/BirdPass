cmake_minimum_required(VERSION 3.12)
project(MyPass)

set(SOURCE_DIR src)
set(CMAKE_BINARY_DIR build)

# 指定可执行文件的源文件
add_executable(BirdPass src/main.cpp src/AES.cpp src/Deco.cpp src/OS.cpp src/sm4.cpp src/TOTP.cpp)

# 指定头文件的包含路径
target_include_directories(BirdPass PRIVATE include)

# 添加 OpenSSL 库的包含路径和链接选项
target_include_directories(BirdPass PRIVATE lib/OpenSSL/include)
target_link_directories(BirdPass PRIVATE lib/OpenSSL/lib)
target_link_libraries(BirdPass PRIVATE ssl)
target_link_libraries(BirdPass PRIVATE crypto)
target_link_libraries(BirdPass PRIVATE OpenSSL)


# 添加其他 DLL 文件的部署路径
file(COPY lib/OpenSSL/bin/libcrypto-3-x64.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY lib/OpenSSL/bin/libssl-3-x64.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR})