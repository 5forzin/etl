#include "browser.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <vector>

namespace {
std::wstring quote(const std::wstring& value) {
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (wchar_t character : value) {
    if (character == L'\\') { ++slashes; continue; }
    result.append(slashes * (character == L'"' ? 2 : 1), L'\\');
    slashes = 0;
    if (character == L'"') result += L'\\';
    result += character;
  }
  result.append(slashes * 2, L'\\');
  return result + L'"';
}

std::wstring registryString(HKEY root, const std::wstring& key, const wchar_t* name = nullptr) {
  DWORD bytes = 0;
  if (RegGetValueW(root, key.c_str(), name, RRF_RT_REG_SZ, nullptr, nullptr, &bytes) != ERROR_SUCCESS ||
      bytes < sizeof(wchar_t) || bytes > 65536) return {};
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t));
  if (RegGetValueW(root, key.c_str(), name, RRF_RT_REG_SZ, nullptr, buffer.data(), &bytes) != ERROR_SUCCESS) return {};
  return buffer.data();
}

std::filesystem::path folder(REFKNOWNFOLDERID id) {
  PWSTR value = nullptr;
  if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &value))) return {};
  std::filesystem::path result(value);
  CoTaskMemFree(value);
  return result;
}

std::filesystem::path findBrowser(const wchar_t* name) {
  const std::wstring key = L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + std::wstring(name);
  for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
    auto path = registryString(root, key);
    if (path.size() > 1 && path.front() == L'"' && path.back() == L'"') path = path.substr(1, path.size() - 2);
    if (!path.empty() && std::filesystem::is_regular_file(path)) return path;
  }
  const bool edge = std::wstring(name) == L"msedge.exe";
  const std::filesystem::path relative = edge ? L"Microsoft\\Edge\\Application\\msedge.exe" :
    L"Google\\Chrome\\Application\\chrome.exe";
  for (REFKNOWNFOLDERID id : {FOLDERID_LocalAppData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86}) {
    const auto root = folder(id);
    if (!root.empty() && std::filesystem::is_regular_file(root / relative)) return root / relative;
  }
  return {};
}
}

bool localProxyAvailable(int port) {
  if (port < 1 || port > 65535) return false;
  SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == INVALID_SOCKET) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(static_cast<unsigned short>(port));
  u_long nonblocking = 1;
  bool ok = ioctlsocket(socket, FIONBIO, &nonblocking) == 0;
  if (ok && connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ok = WSAGetLastError() == WSAEWOULDBLOCK;
    if (ok) {
      fd_set writable; FD_ZERO(&writable); FD_SET(socket, &writable);
      timeval limit{0, 300000};
      ok = select(0, nullptr, &writable, nullptr, &limit) > 0;
    }
  }
  int error = 1, length = sizeof(error);
  ok = ok && getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
  nonblocking = 0;
  DWORD timeout = 300;
  ok = ok && ioctlsocket(socket, FIONBIO, &nonblocking) == 0 &&
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout)) == 0 &&
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout)) == 0;
  const char greeting[]{5, 1, 0};
  char reply[2]{};
  if (ok) ok = send(socket, greeting, sizeof(greeting), 0) == sizeof(greeting);
  int received = 0;
  while (ok && received < 2) {
    const int count = recv(socket, reply + received, 2 - received, 0);
    if (count <= 0) { ok = false; break; }
    received += count;
  }
  closesocket(socket);
  return ok && reply[0] == 5 && reply[1] == 0;
}

bool startProxyBrowser(const std::filesystem::path& executable,
  const std::filesystem::path& profile, int port, std::wstring& error) {
  if (port < 1 || port > 65535) { error = L"Check the local proxy port."; return false; }
  std::error_code ec;
  std::filesystem::create_directories(profile, ec);
  if (ec) { error = L"The browser profile could not be created."; return false; }
  const std::vector<std::wstring> arguments{
    executable.wstring(), L"--user-data-dir=" + profile.wstring(),
    L"--proxy-server=socks5://127.0.0.1:" + std::to_wstring(port),
    L"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    L"--disable-quic", L"--no-first-run", L"--no-default-browser-check",
    L"--new-window", L"about:blank"};
  std::wstring command;
  for (const auto& argument : arguments) {
    if (!command.empty()) command += L' ';
    command += quote(argument);
  }
  STARTUPINFOW startup{}; startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
      CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, nullptr, executable.parent_path().c_str(), &startup, &process)) {
    error = L"The browser could not start.";
    return false;
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return true;
}

bool openProxyBrowser(int port, std::wstring& error) {
  try {
    const auto preferred = registryString(HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice", L"ProgId");
    const bool preferEdge = preferred.find(L"MSEdge") != std::wstring::npos;
    auto executable = findBrowser(preferEdge ? L"msedge.exe" : L"chrome.exe");
    if (executable.empty()) executable = findBrowser(preferEdge ? L"chrome.exe" : L"msedge.exe");
    if (executable.empty()) { error = L"Install Chrome or Edge to open a proxy browser."; return false; }
    const auto root = folder(FOLDERID_LocalAppData);
    if (root.empty()) { error = L"The browser profile directory is unavailable."; return false; }
    // Chromium reuses the process for a user-data directory. A profile per
    // browser and port keeps an existing session's proxy flags from being reused.
    const auto profile = root / L"ETL" / L"Browser" /
      (executable.stem().wstring() + L"-" + std::to_wstring(port));
    return startProxyBrowser(executable, profile, port, error);
  } catch (const std::filesystem::filesystem_error&) {
    error = L"The browser installation or profile could not be accessed.";
    return false;
  }
}
