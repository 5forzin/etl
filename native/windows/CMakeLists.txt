cmake_minimum_required(VERSION 3.20)
project(etl_windows_client LANGUAGES CXX)
enable_language(RC)
include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../../package.json" ETL_PACKAGE)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../../package.json")
string(JSON ETL_VERSION GET "${ETL_PACKAGE}" version)
string(REPLACE "." "," ETL_RESOURCE_VERSION "${ETL_VERSION}.0")
get_filename_component(ETL_ICON_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../assets/brand/etl.ico" ABSOLUTE)

# hev-socks5-tunnel 2.19.0 win64 (TUN engine for VPN mode), pinned by checksum:
# the zip hash anchors the download and per-component hashes anchor extraction.
set(ETL_HEV_URL https://github.com/heiher/hev-socks5-tunnel/releases/download/2.19.0/hev-socks5-tunnel-win64.zip)
set(ETL_HEV_ZIP_SHA256 3affbcdd00d699430768bcfa8b79b854a951e30bbb11b011ebb3f7f01aa09928)
file(DOWNLOAD ${ETL_HEV_URL} "${CMAKE_CURRENT_BINARY_DIR}/hev-win64.zip"
  EXPECTED_HASH SHA256=${ETL_HEV_ZIP_SHA256} SHOW_PROGRESS)
file(ARCHIVE_EXTRACT INPUT "${CMAKE_CURRENT_BINARY_DIR}/hev-win64.zip"
  DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/hev-runtime" PATTERNS "hev-socks5-tunnel/*")
set(ETL_HEV_DIR "${CMAKE_CURRENT_BINARY_DIR}/hev-runtime/hev-socks5-tunnel")
set(ETL_HEV_COMPONENTS
  "hev-socks5-tunnel.exe=0e4274ee9e1b30e180d7df10bf244586234e0cf196650d3fcb51320b6e2bf5f9"
  "msys-2.0.dll=1410599ee2efcede0869abec8910398d688755952e59cf7983b15cac6de78201"
  "wintun.dll=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
foreach(component ${ETL_HEV_COMPONENTS})
  string(REGEX MATCH "^([^=]+)=(.+)$" matched "${component}")
  file(SHA256 "${ETL_HEV_DIR}/${CMAKE_MATCH_1}" component_hash)
  if(NOT component_hash STREQUAL CMAKE_MATCH_2)
    message(FATAL_ERROR "Runtime component ${CMAKE_MATCH_1} hash mismatch")
  endif()
endforeach()

configure_file(etl-client.rc.in "${CMAKE_CURRENT_BINARY_DIR}/etl-client.rc" @ONLY)
configure_file(etl_version.h.in "${CMAKE_CURRENT_BINARY_DIR}/etl_version.h" @ONLY)

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
# JSON for Modern C++ 3.12.0, pinned by archive checksum.
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa)
FetchContent_MakeAvailable(json)
add_library(etl-updater STATIC updater.cpp)
target_include_directories(etl-updater PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_features(etl-updater PUBLIC cxx_std_17)
target_compile_definitions(etl-updater PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0602)
target_link_libraries(etl-updater PUBLIC nlohmann_json::nlohmann_json OpenSSL::Crypto winhttp advapi32 ole32 ws2_32 crypt32)
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
add_executable(etl-client WIN32 etl_client.cpp vpn.cpp browser.cpp desktop_session.cpp "${CMAKE_CURRENT_BINARY_DIR}/etl-client.rc")
target_include_directories(etl-client PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(etl-client PRIVATE cxx_std_17)
target_compile_definitions(etl-client PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0602)
target_link_libraries(etl-client PRIVATE etl-ui etl-updater OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32 shell32 ole32 iphlpapi)
if(MSVC)
  target_compile_options(etl-client PRIVATE /utf-8 /W4)
  target_compile_options(etl-ui PRIVATE /utf-8)
  target_compile_options(etl-updater PRIVATE /utf-8 /W4)
endif()
add_custom_command(TARGET etl-client POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy "${imgui_SOURCE_DIR}/LICENSE.txt" "$<TARGET_FILE_DIR:etl-client>/LICENSE-ImGui.txt"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/assets/LICENSE-Inter.txt" "$<TARGET_FILE_DIR:etl-client>/LICENSE-Inter.txt")
add_custom_command(TARGET etl-client POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy "${json_SOURCE_DIR}/LICENSE.MIT" "$<TARGET_FILE_DIR:etl-client>/LICENSE-JSON.txt")
enable_testing()
add_executable(etl-update-tests test_update.cpp)
target_compile_definitions(etl-update-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(etl-update-tests PRIVATE etl-updater)
add_test(NAME updater COMMAND etl-update-tests)
set_tests_properties(updater PROPERTIES TIMEOUT 45)
add_executable(etl-vpn-tests test_vpn.cpp vpn.cpp)
target_compile_features(etl-vpn-tests PRIVATE cxx_std_17)
target_compile_definitions(etl-vpn-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0602)
target_link_libraries(etl-vpn-tests PRIVATE OpenSSL::Crypto ws2_32 shell32 ole32 iphlpapi)
add_test(NAME vpn-health COMMAND etl-vpn-tests)
set_tests_properties(vpn-health PROPERTIES TIMEOUT 10)
add_executable(etl-browser-tests test_browser.cpp browser.cpp)
target_compile_features(etl-browser-tests PRIVATE cxx_std_17)
target_compile_definitions(etl-browser-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(etl-browser-tests PRIVATE ws2_32 shell32 ole32 advapi32)
add_test(NAME browser-session COMMAND etl-browser-tests)
set_tests_properties(browser-session PROPERTIES TIMEOUT 10)
add_executable(etl-session-tests test_desktop_session.cpp desktop_session.cpp)
target_compile_features(etl-session-tests PRIVATE cxx_std_17)
target_compile_definitions(etl-session-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(etl-session-tests PRIVATE shell32 ole32 advapi32)
add_test(NAME desktop-session COMMAND etl-session-tests)
set_tests_properties(desktop-session PROPERTIES TIMEOUT 15)
if(MINGW)
  target_link_options(etl-session-tests PRIVATE -municode)
  target_link_options(etl-browser-tests PRIVATE -municode)
  target_link_options(etl-client PRIVATE -municode -static-libgcc -static-libstdc++)
  if(ETL_PORTABLE)
    target_link_options(etl-client PRIVATE -static)
  endif()
endif()
