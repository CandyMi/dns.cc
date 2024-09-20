# 作者信息
message("======================================")
message("Project Name   : Xdns")
message("Author  Name   : CandyMi")
message("Author  Email  : 869646063@qq.com")
message("Author  Github : github.com/CandyMi")
message("======================================")

# 项目名称
project("Xdns")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_MACOSX_RPATH 1)
else()
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

# 最低版本号
cmake_minimum_required(VERSION 2.8...3.13)

# 忽略警告
set(CMAKE_LEGACY_CYGWIN_WIN32 0)

# 文件列表
file(GLOB xdns_src ${CMAKE_SOURCE_DIR}/src/*.cc)

if (MSVC)
  add_compile_options(/Za)
endif()

# 构建静态库
add_library(xdns_object OBJECT ${xdns_src})
# 动态库
add_library(xdns-a STATIC $<TARGET_OBJECTS:xdns_object>)
# 静态库
add_library(xdns-dll SHARED $<TARGET_OBJECTS:xdns_object>)

if(WIN32)
  set_target_properties(xdns-dll PROPERTIES OUTPUT_NAME "xdns" PREFIX "" )
  set_target_properties(xdns-a PROPERTIES OUTPUT_NAME "xdns" PREFIX "")
else()
  set_target_properties(xdns-dll PROPERTIES OUTPUT_NAME "xdns" PREFIX "lib")
  set_target_properties(xdns-a PROPERTIES OUTPUT_NAME "xdns" PREFIX "lib")
endif(WIN32)

# 如果存在main.c测试文件，则添加可执行文件
if (EXISTS ${CMAKE_SOURCE_DIR}/main.c)
  add_executable(main main.c)
  target_link_libraries(main PRIVATE xdns_object)
endif()

install(
  TARGETS xdns-a xdns-dll
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libxdns.a
  LIBRARY  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libxdns.[so|dll]
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include     # include
)
