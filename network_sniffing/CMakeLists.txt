cmake_minimum_required(VERSION 3.24)
project(linpcap_pro C)

set(CMAKE_C_STANDARD 11)

# 查找libpcap库
find_library(PCAP_LIBRARY pcap)

# 声明头文件路径
set(INC_DIR /usr/include)

# 引入头文件
include_directories(${INC_DIR})

# 添加可执行文件
add_executable(linpcap_pro main.c)

# 链接libpcap库
target_link_libraries(linpcap_pro ${PCAP_LIBRARY})


