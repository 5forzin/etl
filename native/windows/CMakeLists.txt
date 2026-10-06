cmake_minimum_required(VERSION 3.20)
project(etl_windows_client LANGUAGES CXX)
enable_language(RC)
include(FetchContent)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../../package.json" ETL_PACKAGE)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../../package.json")
string(JSON ETL_VERSION GET "${ETL_PACKAGE}" version)
string(REPLACE "." "," ETL_RESOURCE_VERSION "${ETL_VERSION}.0")
get_filename_component(ETL_ICON_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../assets/brand/etl.ico" ABSOLUTE)
configure_file(etl-client.rc.in "${CMAKE_CURRENT_BINARY_DIR}/etl-client.rc" @ONLY)

option(ETL_PORTABLE "Build a single EXE without MSYS2 runtime DLLs" OFF)
if(ETL_PORTABLE)
  if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL REQUIRED)
# Reviewed release, pinned to a commit rather than a moving branch.
FetchContent_Declare(imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG 6d910d5487d11ca567b61c7824b0c78c569d62f0)
FetchContent_MakeAvailable(imgui)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/assets/InterVariable.ttf" ETL_FONT_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," ETL_FONT_BYTES "${ETL_FONT_HEX}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/etl_font.h"
  "static const unsigned char etlFont[] = {${ETL_FONT_BYTES}};\n")
add_library(etl-ui STATIC desktop_ui.cpp
  ${imgui_SOURCE_DIR}/imgui.cpp ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp)
target_include_directories(etl-ui PUBLIC ${imgui_SOURCE_DIR} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_features(etl-ui PUBLIC cxx_std_17)
target_compile_definitions(etl-ui PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(etl-ui PUBLIC d3d11 dxgi d3dcompiler dwmapi)
add_executable(etl-client WIN32 etl_client.cpp "${CMAKE_CURRENT_BINARY_DIR}/etl-client.rc")
target_include_directories(etl-client PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(etl-client PRIVATE cxx_std_17)
target_compile_definitions(etl-client PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0602)
target_link_libraries(etl-client PRIVATE etl-ui OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32 shell32 ole32)
if(MSVC)
  target_compile_options(etl-client PRIVATE /utf-8 /W4)
  target_compile_options(etl-ui PRIVATE /utf-8)
endif()
add_custom_command(TARGET etl-client POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy "${imgui_SOURCE_DIR}/LICENSE.txt" "$<TARGET_FILE_DIR:etl-client>/LICENSE-ImGui.txt"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/assets/LICENSE-Inter.txt" "$<TARGET_FILE_DIR:etl-client>/LICENSE-Inter.txt")
if(MINGW)
  target_link_options(etl-client PRIVATE -municode -static-libgcc -static-libstdc++)
  if(ETL_PORTABLE)
    target_link_options(etl-client PRIVATE -static)
  endif()
endif()
