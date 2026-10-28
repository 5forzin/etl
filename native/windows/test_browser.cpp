#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
#include "browser.h"

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

static bool proxyProbe(bool valid) {
  SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
    listen(listener, 1) == 0, "Cannot start local proxy fixture");
  int length = sizeof(address);
  require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0,
    "Cannot determine local proxy port");
  std::thread server([&] {
    SOCKET peer = accept(listener, nullptr, nullptr);
    char greeting[3]{};
    if (peer == INVALID_SOCKET) return;
    DWORD timeout = 1000;
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    recv(peer, greeting, sizeof(greeting), 0);
    const char method = valid ? 5 : 0;
    send(peer, &method, 1, 0);
    Sleep(10);
    const char accepted = 0;
    send(peer, &accepted, 1, 0);
    closesocket(peer);
  });
  const bool ready = localProxyAvailable(ntohs(address.sin_port));
  server.join();
  closesocket(listener);
  return ready;
}

int wmain(int argc, wchar_t** argv) {
  if (argc > 1 && std::wstring(argv[1]).rfind(L"--user-data-dir=", 0) == 0) {
    const auto directory = std::filesystem::path(std::wstring(argv[1]).substr(16));
    std::ofstream output(directory / L"arguments.bin", std::ios::binary);
    for (int i = 1; i < argc; ++i)
      output.write(reinterpret_cast<const char*>(argv[i]), (wcslen(argv[i]) + 1) * sizeof(wchar_t));
    return output.good() ? 0 : 1;
  }
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
  wchar_t temporary[MAX_PATH]{}, executable[32768]{};
  GetTempPathW(MAX_PATH, temporary);
  GetModuleFileNameW(nullptr, executable, 32768);
  const auto directory = std::filesystem::path(temporary) /
    (L"etl-browser-tests-" + std::to_wstring(GetCurrentProcessId()));
  try {
    require(proxyProbe(true), "Valid local SOCKS proxy was not recognized");
    require(!proxyProbe(false), "Non-SOCKS listener was accepted");
    require(!localProxyAvailable(0) && !localProxyAvailable(65536), "Invalid proxy port accepted");
    const auto profile = directory / L"Browser session \u00e9";
    std::wstring error;
    require(startProxyBrowser(executable, profile, 1087, error), "Browser fixture did not start");
    const auto outputPath = profile / L"arguments.bin";
    for (int i = 0; i < 60 && !std::filesystem::exists(outputPath); ++i) Sleep(50);
    std::ifstream output(outputPath, std::ios::binary);
    std::vector<char> bytes((std::istreambuf_iterator<char>(output)), {});
    output.close();
    require(!bytes.empty() && bytes.size() % sizeof(wchar_t) == 0, "Browser did not capture arguments");
    std::wstring arguments(bytes.size() / sizeof(wchar_t), L'\0');
    memcpy(arguments.data(), bytes.data(), bytes.size());
    const auto contains = [&](const std::wstring& argument) {
      return arguments.find(argument + L'\0') != std::wstring::npos;
    };
    require(contains(L"--user-data-dir=" + profile.wstring()), "Profile path quoting failed");
    require(contains(L"--proxy-server=socks5://127.0.0.1:1087"), "Configured proxy port was ignored");
    require(contains(L"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"), "Remote DNS rule was split");
    require(contains(L"--disable-quic") && contains(L"--new-window") && contains(L"about:blank"),
      "Proxy browser flags are incomplete");
    require(!startProxyBrowser(executable, profile, -1, error), "Invalid browser proxy port accepted");
    require(!startProxyBrowser(directory / L"missing.exe", profile, 1087, error), "Missing browser accepted");
    std::filesystem::remove_all(directory);
    std::cout << "Browser launch and local proxy checks passed\n";
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    std::filesystem::remove_all(directory);
    WSACleanup(); return 1;
  }
  WSACleanup(); return 0;
}
