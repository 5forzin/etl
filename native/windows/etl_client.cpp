#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include "desktop_ui.h"
#include <windowsx.h>
#include <dwmapi.h>

constexpr UINT WM_TRAY = WM_APP + 1;
constexpr UINT WM_SERVICE_STOPPED = WM_APP + 2;
constexpr int ID_CONNECT = 101;
constexpr int ID_SERVER = 102;
constexpr int ID_SERVER_PORT = 103;
constexpr int ID_TOKEN = 104;
constexpr int ID_LOCAL_PORT = 105;
constexpr int ID_CA = 106;
constexpr int ID_STATUS = 107;
constexpr int ID_FALLBACK_SERVER = 108;
constexpr int ID_FALLBACK_PORT = 109;
constexpr int ID_FALLBACK_TOKEN = 110;
constexpr int ID_CONNECT_TIMEOUT = 111;
constexpr int ID_OPEN = 201;
constexpr int ID_EXIT = 202;

struct Config {
  std::wstring server = L"etl.nora.systems";
  int serverPort = 443;
  std::wstring protectedToken;
  // Kept for headless automation; the desktop UI accepts the token directly.
  std::wstring tokenFile;
  std::wstring fallbackServer;
  int fallbackPort = 443;
  std::wstring fallbackProtectedToken;
  std::wstring fallbackTokenFile;
  int connectTimeoutMs = 1000;
  int handshakeTimeoutMs = 10000;
  int idleTimeoutMs = 120000;
  int localPort = 1080;
  std::wstring caFile;
};

static std::string utf8(const std::wstring& value) {
  int n = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), n, nullptr, nullptr);
  out.pop_back();
  return out;
}

static bool portValue(const std::wstring& value, int& result) {
  if (value.empty() || value.size() > 5 ||
      !std::all_of(value.begin(), value.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; })) return false;
  int parsed = std::stoi(value);
  if (parsed < 1 || parsed > 65535) return false;
  result = parsed;
  return true;
}

static std::wstring configPath() {
  PWSTR root = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &root))) return L"etl.ini";
  std::filesystem::path dir = std::filesystem::path(root) / L"ETL";
  CoTaskMemFree(root);
  std::filesystem::create_directories(dir);
  return (dir / L"settings.ini").wstring();
}

static std::wstring readSetting(const std::wstring& path, const wchar_t* name, const wchar_t* fallback) {
  wchar_t buffer[1024]{};
  GetPrivateProfileStringW(L"client", name, fallback, buffer, 1024, path.c_str());
  return buffer;
}

static bool validToken(const std::string& token) {
  return token.size() == 64 && std::all_of(token.begin(), token.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}

static bool readToken(const std::wstring& path, std::string& token) {
  std::ifstream file(std::filesystem::path(path), std::ios::binary);
  if (!file) return false;
  file.seekg(0, std::ios::end);
  if (file.tellg() > 256) return false;
  file.seekg(0);
  token.assign(std::istreambuf_iterator<char>(file), {});
  while (!token.empty() && (token.back() == '\n' || token.back() == '\r' || token.back() == ' ')) token.pop_back();
  if (validToken(token)) return true;
  OPENSSL_cleanse(token.data(), token.size());
  token.clear();
  return false;
}

static bool protectToken(const std::string& token, std::wstring& encoded) {
  if (!validToken(token)) return false;
  DATA_BLOB plain{static_cast<DWORD>(token.size()), reinterpret_cast<BYTE*>(const_cast<char*>(token.data()))};
  DATA_BLOB protectedData{};
  if (!CryptProtectData(&plain, L"ETL token", nullptr, nullptr, nullptr,
                        CRYPTPROTECT_UI_FORBIDDEN, &protectedData)) return false;
  constexpr wchar_t digits[] = L"0123456789abcdef";
  encoded.clear();
  encoded.reserve(protectedData.cbData * 2);
  for (DWORD i = 0; i < protectedData.cbData; ++i) {
    encoded += digits[protectedData.pbData[i] >> 4];
    encoded += digits[protectedData.pbData[i] & 15];
  }
  LocalFree(protectedData.pbData);
  return true;
}

static bool unprotectToken(const std::wstring& encoded, std::string& token) {
  if (encoded.empty() || encoded.size() % 2 || encoded.size() > 2048) return false;
  auto digit = [](wchar_t c) -> int {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    return -1;
  };
  std::vector<BYTE> bytes;
  bytes.reserve(encoded.size() / 2);
  for (size_t i = 0; i < encoded.size(); i += 2) {
    int high = digit(encoded[i]), low = digit(encoded[i + 1]);
    if (high < 0 || low < 0) return false;
    bytes.push_back(static_cast<BYTE>((high << 4) | low));
  }
  DATA_BLOB protectedData{static_cast<DWORD>(bytes.size()), bytes.data()};
  DATA_BLOB plain{};
  if (!CryptUnprotectData(&protectedData, nullptr, nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &plain)) return false;
  token.assign(reinterpret_cast<char*>(plain.pbData), plain.cbData);
  SecureZeroMemory(plain.pbData, plain.cbData);
  LocalFree(plain.pbData);
  if (validToken(token)) return true;
  OPENSSL_cleanse(token.data(), token.size());
  token.clear();
  return false;
}

static bool tokenForConfig(const Config& config, std::string& token, bool fallback = false) {
  if (fallback && !config.fallbackProtectedToken.empty()) return unprotectToken(config.fallbackProtectedToken, token);
  if (fallback && !config.fallbackTokenFile.empty()) return readToken(config.fallbackTokenFile, token);
  if (!config.protectedToken.empty()) return unprotectToken(config.protectedToken, token);
  return !config.tokenFile.empty() && readToken(config.tokenFile, token);
}

static Config loadConfig() {
  Config c;
  auto path = configPath();
  c.server = readSetting(path, L"server", c.server.c_str());
  c.protectedToken = readSetting(path, L"token_protected", L"");
  c.fallbackServer = readSetting(path, L"fallback_server", L"");
  c.fallbackProtectedToken = readSetting(path, L"fallback_token_protected", L"");
  c.caFile = readSetting(path, L"ca_file", L"");
  int value;
  if (portValue(readSetting(path, L"server_port", L"443"), value)) c.serverPort = value;
  if (portValue(readSetting(path, L"local_port", L"1080"), value)) c.localPort = value;
  if (portValue(readSetting(path, L"fallback_port", L"443"), value)) c.fallbackPort = value;
  if (portValue(readSetting(path, L"connect_timeout_ms", L"1000"), value) && value <= 60000) c.connectTimeoutMs = value;
  if (c.protectedToken.empty()) {
    const auto legacyFile = readSetting(path, L"token_file", L"");
    std::string token;
    if (!legacyFile.empty() && readToken(legacyFile, token) && protectToken(token, c.protectedToken)) {
      if (WritePrivateProfileStringW(L"client", L"token_protected", c.protectedToken.c_str(), path.c_str())) {
        WritePrivateProfileStringW(L"client", L"token_file", nullptr, path.c_str());
      }
    }
    OPENSSL_cleanse(token.data(), token.size());
  }
  return c;
}

static bool saveConfig(const Config& c) {
  auto path = configPath();
  bool ok = WritePrivateProfileStringW(L"client", L"server", c.server.c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"server_port", std::to_wstring(c.serverPort).c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"token_protected", c.protectedToken.c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"fallback_server", c.fallbackServer.c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"fallback_port", std::to_wstring(c.fallbackPort).c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"fallback_token_protected", c.fallbackProtectedToken.c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"connect_timeout_ms", std::to_wstring(c.connectTimeoutMs).c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"local_port", std::to_wstring(c.localPort).c_str(), path.c_str()) &&
    WritePrivateProfileStringW(L"client", L"ca_file", c.caFile.c_str(), path.c_str());
  if (ok) ok = WritePrivateProfileStringW(L"client", L"token_file", nullptr, path.c_str());
  return ok;
}

static bool socketRead(SOCKET s, void* p, size_t n, const std::atomic<bool>& running) {
  char* out = static_cast<char*>(p);
  while (n && running) {
    fd_set readable; FD_ZERO(&readable); FD_SET(s, &readable);
    timeval pollTimeout{0, 250000};
    int ready = select(0, &readable, nullptr, nullptr, &pollTimeout);
    if (!running || ready == SOCKET_ERROR) return false;
    if (ready == 0) continue;
    int count = recv(s, out, static_cast<int>(std::min<size_t>(n, 16384)), 0);
    if (count <= 0) return false;
    out += count; n -= count;
  }
  return n == 0;
}

static bool socketWrite(SOCKET s, const void* p, size_t n) {
  const char* in = static_cast<const char*>(p);
  while (n) {
    int count = send(s, in, static_cast<int>(std::min<size_t>(n, 16384)), 0);
    if (count <= 0) return false;
    in += count; n -= count;
  }
  return true;
}

static bool sslRead(SSL* ssl, void* p, size_t n) {
  char* out = static_cast<char*>(p);
  while (n) {
    int count = SSL_read(ssl, out, static_cast<int>(std::min<size_t>(n, 16384)));
    if (count <= 0) return false;
    out += count; n -= count;
  }
  return true;
}

static bool sslWrite(SSL* ssl, const void* p, size_t n) {
  const char* in = static_cast<const char*>(p);
  while (n) {
    int count = SSL_write(ssl, in, static_cast<int>(std::min<size_t>(n, 16384)));
    if (count <= 0) return false;
    in += count; n -= count;
  }
  return true;
}

static bool writeFrame(SSL* ssl, const std::string& body) {
  if (body.size() < 2 || body.size() > 1024) return false;
  unsigned char size[2]{static_cast<unsigned char>(body.size() >> 8), static_cast<unsigned char>(body.size())};
  return sslWrite(ssl, size, 2) && sslWrite(ssl, body.data(), body.size());
}

static bool responseOK(SSL* ssl) {
  unsigned char size[2];
  if (!sslRead(ssl, size, 2)) return false;
  size_t n = (size_t(size[0]) << 8) | size[1];
  if (n < 2 || n > 1024) return false;
  std::string body(n, '\0');
  return sslRead(ssl, body.data(), n) && body == "{\"code\":\"OK\"}";
}

// A socket timeout resets whenever bytes arrive; a protocol deadline must not.
class SocketBudget {
 public:
  SocketBudget(SOCKET socket, int milliseconds) : guard_([this, socket, milliseconds] {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!wake_.wait_for(lock, std::chrono::milliseconds(milliseconds), [this] { return done_; })) {
      shutdown(socket, SD_BOTH);
    }
  }) {}
  void cancel() {
    { std::lock_guard<std::mutex> lock(mutex_); done_ = true; }
    wake_.notify_one();
    if (guard_.joinable()) guard_.join();
  }
  ~SocketBudget() { cancel(); }
 private:
  std::mutex mutex_;
  std::condition_variable wake_;
  bool done_ = false;
  std::thread guard_;
};

static std::string jsonEscape(const std::string& value) {
  std::string out;
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
    else if (c >= 0x20 && c < 0x7f) out += char(c);
    else return {};
  }
  return out;
}

static void socksReply(SOCKET s, unsigned char code) {
  const unsigned char reply[]{5, code, 0, 1, 0, 0, 0, 0, 0, 0};
  socketWrite(s, reply, sizeof(reply));
}

static bool socksRequest(SOCKET s, std::string& host, int& port, const std::atomic<bool>& running) {
  unsigned char header[4]{5};
  if (!socketRead(s, header + 1, 1, running) || header[1] == 0) return false;
  std::vector<unsigned char> methods(header[1]);
  if (!socketRead(s, methods.data(), methods.size(), running)) return false;
  if (std::find(methods.begin(), methods.end(), 0) == methods.end()) {
    const unsigned char reject[]{5, 255}; socketWrite(s, reject, 2); return false;
  }
  const unsigned char accepted[]{5, 0};
  if (!socketWrite(s, accepted, 2) || !socketRead(s, header, 4, running) || header[0] != 5 || header[2] != 0) return false;
  if (header[1] != 1) { socksReply(s, 7); return false; }
  char address[INET6_ADDRSTRLEN]{};
  if (header[3] == 1 || header[3] == 4) {
    unsigned char bytes[16];
    int count = header[3] == 1 ? 4 : 16;
    if (!socketRead(s, bytes, count, running)) return false;
    if (!InetNtopA(count == 4 ? AF_INET : AF_INET6, bytes, address, sizeof(address))) return false;
    host = address;
  } else if (header[3] == 3) {
    unsigned char n;
    if (!socketRead(s, &n, 1, running) || n == 0) return false;
    host.resize(n);
    if (!socketRead(s, host.data(), n, running)) return false;
  } else { socksReply(s, 8); return false; }
  unsigned char bytes[2];
  if (!socketRead(s, bytes, 2, running)) return false;
  port = (int(bytes[0]) << 8) | bytes[1];
  return port > 0 && !jsonEscape(host).empty();
}

struct HttpRequest {
  std::string host;
  int port = 0;
  std::string initialData;
  bool connect = false;
};

static bool parseAuthority(const std::string& authority, int defaultPort, std::string& host, int& port) {
  if (authority.empty() || authority.size() > 261) return false;
  std::string portText;
  if (authority[0] == '[') {
    size_t end = authority.find(']');
    if (end == std::string::npos) return false;
    host = authority.substr(1, end - 1);
    if (end + 1 < authority.size()) {
      if (authority[end + 1] != ':') return false;
      portText = authority.substr(end + 2);
    }
  } else {
    size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      if (authority.find(':') != colon) return false;
      host = authority.substr(0, colon);
      portText = authority.substr(colon + 1);
    } else host = authority;
  }
  if (host.empty() || host.size() > 253 || jsonEscape(host) != host ||
      host.find_first_of(" /?#@\\") != std::string::npos) return false;
  port = defaultPort;
  if (!portText.empty()) {
    if (portText.size() > 5 || !std::all_of(portText.begin(), portText.end(), [](char c) { return c >= '0' && c <= '9'; })) return false;
    port = std::stoi(portText);
  } else if (defaultPort == 0 || authority.back() == ':') return false;
  return port >= 1 && port <= 65535;
}

static std::string lowerAscii(std::string value) {
  for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

static bool httpRequest(SOCKET s, char first, HttpRequest& result, const std::atomic<bool>& running) {
  std::string request(1, first);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (request.size() < 8192 && running && std::chrono::steady_clock::now() < deadline) {
    if (request.size() >= 4 && request.compare(request.size() - 4, 4, "\r\n\r\n") == 0) break;
    fd_set readable; FD_ZERO(&readable); FD_SET(s, &readable);
    timeval pollTimeout{0, 250000};
    int ready = select(0, &readable, nullptr, nullptr, &pollTimeout);
    if (ready == SOCKET_ERROR) return false;
    if (!ready) continue;
    char byte;
    if (recv(s, &byte, 1, 0) != 1 || byte == '\0') return false;
    request += byte;
  }
  if (request.size() < 4 || request.compare(request.size() - 4, 4, "\r\n\r\n") != 0) return false;
  size_t lineEnd = request.find("\r\n");
  if (lineEnd == std::string::npos) return false;
  const std::string line = request.substr(0, lineEnd);
  size_t firstSpace = line.find(' '), lastSpace = line.rfind(' ');
  if (firstSpace == std::string::npos || lastSpace == firstSpace || line.find(' ', firstSpace + 1) != lastSpace) return false;
  std::string method = line.substr(0, firstSpace);
  std::string target = line.substr(firstSpace + 1, lastSpace - firstSpace - 1);
  std::string version = line.substr(lastSpace + 1);
  if (method.empty() || method.size() > 16 ||
      !std::all_of(method.begin(), method.end(), [](char c) { return c >= 'A' && c <= 'Z'; }) ||
      (version != "HTTP/1.0" && version != "HTTP/1.1")) return false;
  if (method == "CONNECT") {
    result.connect = true;
    return parseAuthority(target, 0, result.host, result.port);
  }
  if (target.compare(0, 7, "http://") != 0) return false;
  size_t pathStart = target.find_first_of("/?", 7);
  std::string authority = target.substr(7, pathStart == std::string::npos ? std::string::npos : pathStart - 7);
  if (!parseAuthority(authority, 80, result.host, result.port)) return false;
  std::string path = pathStart == std::string::npos ? "/" : target.substr(pathStart);
  if (path[0] == '?') path.insert(path.begin(), '/');
  if (path.find('#') != std::string::npos) return false;
  result.initialData = method + " " + path + " " + version + "\r\n";
  bool hasHost = false;
  for (size_t start = lineEnd + 2; start + 2 < request.size();) {
    size_t end = request.find("\r\n", start);
    if (end == std::string::npos) return false;
    if (end == start) break;
    std::string header = request.substr(start, end - start);
    size_t colon = header.find(':');
    if (colon == std::string::npos) return false;
    std::string name = lowerAscii(header.substr(0, colon));
    if (name == "host") hasHost = true;
    if (name != "connection" && name != "proxy-connection" && name != "proxy-authorization") {
      result.initialData += header + "\r\n";
    }
    start = end + 2;
  }
  if (!hasHost) result.initialData += "Host: " + authority + "\r\n";
  result.initialData += "Connection: close\r\n\r\n";
  return true;
}

static void httpReply(SOCKET s, int status) {
  const char* response = status == 200 ? "HTTP/1.1 200 Connection Established\r\n\r\n" :
    status == 400 ? "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n" :
    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
  socketWrite(s, response, strlen(response));
}

using ConnectClock = std::chrono::steady_clock;

static SOCKET connectServer(const std::wstring& host, int port, const std::atomic<bool>& running,
                            ConnectClock::time_point deadline) {
  if (!running) return INVALID_SOCKET;
  // Some MinGW header releases omit these Windows 8 APIs. Resolve the OS
  // exports directly so the portable build still supports cancellable DNS.
  using CancelLookup = INT (WSAAPI*)(LPHANDLE);
  using LookupResult = INT (WSAAPI*)(LPOVERLAPPED);
  HMODULE winsock = GetModuleHandleW(L"ws2_32.dll");
  auto cancelLookup = reinterpret_cast<CancelLookup>(GetProcAddress(winsock, "GetAddrInfoExCancel"));
  auto completedLookup = reinterpret_cast<LookupResult>(GetProcAddress(winsock, "GetAddrInfoExOverlappedResult"));
  if (!cancelLookup || !completedLookup) return INVALID_SOCKET;
  ADDRINFOEXW hint{}; hint.ai_socktype = SOCK_STREAM; hint.ai_protocol = IPPROTO_TCP;
  ADDRINFOEXW* addresses = nullptr;
  auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - ConnectClock::now()).count();
  if (remaining <= 0) return INVALID_SOCKET;
  OVERLAPPED lookup{};
  lookup.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!lookup.hEvent) return INVALID_SOCKET;
  HANDLE cancellation = nullptr;
  const auto service = std::to_wstring(port);
  int lookupResult = GetAddrInfoExW(host.c_str(), service.c_str(), NS_DNS, nullptr, &hint,
                                    &addresses, nullptr, &lookup, nullptr, &cancellation);
  if (lookupResult == WSA_IO_PENDING) {
    bool completed = false;
    while (running && ConnectClock::now() < deadline) {
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - ConnectClock::now()).count();
      DWORD waited = WaitForSingleObject(lookup.hEvent, static_cast<DWORD>(std::max<int64_t>(1, std::min<int64_t>(100, ms))));
      if (waited == WAIT_OBJECT_0) { completed = true; break; }
      if (waited == WAIT_FAILED) break;
    }
    if (!completed) {
      cancelLookup(&cancellation);
      // Keep the result and OVERLAPPED storage alive until cancellation finishes.
      WaitForSingleObject(lookup.hEvent, INFINITE);
    }
    lookupResult = completedLookup(&lookup);
  }
  CloseHandle(lookup.hEvent);
  if (lookupResult || !running || ConnectClock::now() >= deadline) {
    if (addresses) FreeAddrInfoExW(addresses);
    return INVALID_SOCKET;
  }
  // Keep the OS-preferred family first, but give the other family a prompt try.
  std::vector<ADDRINFOEXW*> preferred, alternate, order;
  int preferredFamily = AF_UNSPEC;
  for (auto* item = addresses; item; item = item->ai_next) {
    if (item->ai_family != AF_INET && item->ai_family != AF_INET6) continue;
    if (preferredFamily == AF_UNSPEC) preferredFamily = item->ai_family;
    (item->ai_family == preferredFamily ? preferred : alternate).push_back(item);
  }
  for (size_t i = 0; i < std::max(preferred.size(), alternate.size()); ++i) {
    if (i < preferred.size()) order.push_back(preferred[i]);
    if (i < alternate.size()) order.push_back(alternate[i]);
  }

  using Clock = ConnectClock;
  const auto remainingBudget = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
  const auto delay = std::max(std::chrono::milliseconds(1),
    std::min(std::chrono::milliseconds(250), remainingBudget / 2));
  constexpr auto poll = std::chrono::milliseconds(100);
  auto nextAttempt = Clock::now();
  size_t next = 0;
  std::vector<SOCKET> pending;
  SOCKET result = INVALID_SOCKET;
  while (running && Clock::now() < deadline) {
    auto now = Clock::now();
    if (next < order.size() && (pending.empty() || now >= nextAttempt)) {
      auto* item = order[next++];
      SOCKET s = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
      if (s != INVALID_SOCKET) {
        u_long nonblocking = 1;
        if (ioctlsocket(s, FIONBIO, &nonblocking) == 0) {
          int rc = connect(s, item->ai_addr, static_cast<int>(item->ai_addrlen));
          if (rc == 0) { result = s; break; }
          int error = WSAGetLastError();
          if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS || error == WSAEALREADY) {
            if (pending.size() == 16) { closesocket(pending.front()); pending.erase(pending.begin()); }
            pending.push_back(s);
            nextAttempt = now + delay;
            continue;
          }
        }
        closesocket(s);
      }
      // A refused or unusable address should not delay the next one.
      nextAttempt = now;
      continue;
    }
    if (pending.empty()) break;
    fd_set writable, exceptional;
    FD_ZERO(&writable); FD_ZERO(&exceptional);
    for (SOCKET s : pending) { FD_SET(s, &writable); FD_SET(s, &exceptional); }
    auto wake = std::min(deadline, now + poll);
    if (next < order.size()) wake = std::min(wake, nextAttempt);
    auto micros = std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::microseconds>(wake - now).count());
    timeval limit{static_cast<long>(micros / 1000000), static_cast<long>(micros % 1000000)};
    int ready = select(0, nullptr, &writable, &exceptional, &limit);
    if (ready == SOCKET_ERROR) {
      for (SOCKET s : pending) closesocket(s);
      pending.clear();
      continue;
    }
    if (ready <= 0) continue;
    for (size_t i = 0; i < pending.size();) {
      SOCKET s = pending[i];
      if (!FD_ISSET(s, &writable) && !FD_ISSET(s, &exceptional)) { ++i; continue; }
      int error = 1, len = sizeof(error);
      bool connected = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len) == 0 && error == 0;
      pending.erase(pending.begin() + i);
      if (connected) { result = s; break; }
      closesocket(s);
    }
    if (result != INVALID_SOCKET) break;
    if (pending.empty()) nextAttempt = Clock::now();
  }
  for (SOCKET s : pending) closesocket(s);
  FreeAddrInfoExW(addresses);
  if (result != INVALID_SOCKET) {
    u_long nonblocking = 0;
    if (ioctlsocket(result, FIONBIO, &nonblocking) != 0 || !running) {
      closesocket(result);
      return INVALID_SOCKET;
    }
    DWORD timeout = static_cast<DWORD>(std::max<int64_t>(1,
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count()));
    setsockopt(result, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    setsockopt(result, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
  }
  return result;
}

static void addWindowsTrust(SSL_CTX* ctx) {
  HCERTSTORE roots = CertOpenSystemStoreW(0, L"ROOT");
  if (!roots) return;
  PCCERT_CONTEXT current = nullptr;
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  while ((current = CertEnumCertificatesInStore(roots, current)) != nullptr) {
    const unsigned char* data = current->pbCertEncoded;
    X509* cert = d2i_X509(nullptr, &data, current->cbCertEncoded);
    if (cert) { X509_STORE_add_cert(store, cert); X509_free(cert); }
  }
  CertCloseStore(roots, 0);
}

class Service {
 public:
  bool start(const Config& config, std::wstring& error) {
    if (running_) return true;
    std::string token;
    if (!tokenForConfig(config, token)) { error = L"Token: use 64 lowercase hex characters."; return false; }
    OPENSSL_cleanse(token.data(), token.size());
    if (!config.fallbackServer.empty() && !tokenForConfig(config, token, true)) {
      error = L"Invalid backup token."; return false;
    }
    OPENSSL_cleanse(token.data(), token.size());
    if (config.connectTimeoutMs < 1 || config.connectTimeoutMs > 60000) { error = L"Timeout: use 1 to 60000 ms."; return false; }
    if (config.server.empty() || config.serverPort < 1 || config.serverPort > 65535 ||
        config.localPort < 1 || config.localPort > 65535 || config.fallbackPort < 1 || config.fallbackPort > 65535 ||
        config.handshakeTimeoutMs < 1 || config.idleTimeoutMs < 1) { error = L"Invalid settings."; return false; }
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) { error = L"TLS could not start."; return false; }
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx_);
    addWindowsTrust(ctx_);
    if (!config.caFile.empty() && SSL_CTX_load_verify_file(ctx_, utf8(config.caFile).c_str()) != 1) {
      error = L"Invalid CA file."; SSL_CTX_free(ctx_); ctx_ = nullptr; return false;
    }
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { error = L"Local listener could not start."; SSL_CTX_free(ctx_); ctx_ = nullptr; return false; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(static_cast<u_short>(config.localPort));
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(listener, SOMAXCONN)) {
      error = L"Local port is busy or unavailable."; closesocket(listener); SSL_CTX_free(ctx_); ctx_ = nullptr; return false;
    }
    config_ = config; listener_ = listener; running_ = true;
    sent_ = 0; received_ = 0; failures_ = 0;
    try { acceptThread_ = std::thread([this] { acceptLoop(); }); }
    catch (...) {
      running_ = false; listener_ = INVALID_SOCKET; closesocket(listener);
      SSL_CTX_free(ctx_); ctx_ = nullptr; error = L"Worker could not start."; return false;
    }
    return true;
  }

  void stop() {
    if (!running_.exchange(false)) return;
    SOCKET listener = listener_.exchange(INVALID_SOCKET);
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (acceptThread_.joinable()) acceptThread_.join();
    // Keep handles stable while interrupting workers; a closed handle may be reused.
    { std::lock_guard<std::mutex> lock(mu_); for (SOCKET s : sockets_) shutdown(s, SD_BOTH); }
    std::unique_lock<std::mutex> lock(mu_);
    drained_.wait(lock, [this] { return sessions_ == 0; });
    lock.unlock();
    SSL_CTX_free(ctx_); ctx_ = nullptr;
  }

  bool running() const { return running_; }
  int sessions() const { return sessions_; }
  uint64_t sent() const { return sent_; }
  uint64_t received() const { return received_; }
  uint64_t failures() const { return failures_; }

 private:
  void acceptLoop() {
    while (running_) {
      SOCKET listener = listener_.load();
      if (listener == INVALID_SOCKET) break;
      fd_set readable; FD_ZERO(&readable); FD_SET(listener, &readable);
      timeval pollTimeout{0, 250000};
      int ready = select(0, &readable, nullptr, nullptr, &pollTimeout);
      if (!running_ || ready == SOCKET_ERROR) break;
      if (ready == 0) continue;
      SOCKET client = accept(listener, nullptr, nullptr);
      if (client == INVALID_SOCKET) break;
      if (!running_ || sessions_ >= 128) { closesocket(client); continue; }
      DWORD receiveTimeout = 1000, sendTimeout = 10000;
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&receiveTimeout), sizeof(receiveTimeout));
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&sendTimeout), sizeof(sendTimeout));
      std::lock_guard<std::mutex> lock(mu_);
      sockets_.insert(client);
      ++sessions_;
      try { std::thread([this, client] {
        try { process(client); } catch (...) { ++failures_; }
        {
          std::lock_guard<std::mutex> lock(mu_);
          sockets_.erase(client);
          closesocket(client);
          --sessions_;
        }
        drained_.notify_all();
      }).detach(); } catch (...) {
        sockets_.erase(client); closesocket(client); --sessions_; ++failures_;
      }
    }
  }

  void process(SOCKET client) {
    SocketBudget negotiation(client, config_.handshakeTimeoutMs);
    std::string host;
    int port = 0;
    unsigned char first;
    if (!socketRead(client, &first, 1, running_) || !running_) return;
    bool socks = first == 5;
    HttpRequest http;
    if (socks) {
      if (!socksRequest(client, host, port, running_)) return;
    } else {
      if (!httpRequest(client, static_cast<char>(first), http, running_)) {
        httpReply(client, 400); return;
      }
      host = http.host; port = http.port;
    }
    negotiation.cancel();
    if (!running_) return;
    SOCKET remote = INVALID_SOCKET;
    SSL* ssl = nullptr;
    bool ok = false;
    const int attempts = config_.fallbackServer.empty() ? 1 : 2;
    for (int attempt = 0; attempt < attempts && running_; ++attempt) {
      const bool fallback = attempt != 0;
      const auto& endpoint = fallback ? config_.fallbackServer : config_.server;
      const int endpointPort = fallback ? config_.fallbackPort : config_.serverPort;
      const auto deadline = ConnectClock::now() + std::chrono::milliseconds(config_.connectTimeoutMs);
      remote = connectServer(endpoint, endpointPort, running_, deadline);
      if (remote == INVALID_SOCKET) continue;
      {
        std::lock_guard<std::mutex> lock(mu_);
        if (!running_) { closesocket(remote); remote = INVALID_SOCKET; break; }
        sockets_.insert(remote);
      }
      // Interrupt blocking OpenSSL calls at the absolute deadline, including
      // peers that keep sending partial control frames. Never retry payloads.
      std::mutex attemptMutex;
      std::condition_variable attemptWake;
      bool attemptDone = false, timedOut = false;
      const SOCKET attemptedSocket = remote;
      std::thread guard([&] {
        std::unique_lock<std::mutex> lock(attemptMutex);
        if (!attemptWake.wait_until(lock, deadline, [&] { return attemptDone; })) {
          timedOut = true;
          shutdown(attemptedSocket, SD_BOTH);
        }
      });
      ssl = SSL_new(ctx_);
      if (ssl) {
        std::string server = utf8(endpoint);
        if (SSL_set_fd(ssl, static_cast<int>(remote)) == 1 &&
            SSL_set_tlsext_host_name(ssl, server.c_str()) == 1 &&
            SSL_set1_host(ssl, server.c_str()) == 1 &&
            SSL_connect(ssl) == 1 && SSL_get_verify_result(ssl) == X509_V_OK) {
          std::string token;
          if (tokenForConfig(config_, token, fallback)) {
            std::string auth;
            auth.reserve(token.size() + 20);
            auth.assign("{\"v\":1,\"token\":\"");
            auth.append(token);
            auth.append("\"}");
            ok = writeFrame(ssl, auth);
            OPENSSL_cleanse(auth.data(), auth.size());
            OPENSSL_cleanse(token.data(), token.size());
            ok = ok && responseOK(ssl);
          }
        }
      }
      { std::lock_guard<std::mutex> lock(attemptMutex); attemptDone = true; }
      attemptWake.notify_one();
      guard.join();
      ok = ok && !timedOut && running_ && ConnectClock::now() < deadline;
      if (ok) break;
      if (ssl) SSL_free(ssl);
      ssl = nullptr;
      { std::lock_guard<std::mutex> lock(mu_); sockets_.erase(remote); }
      closesocket(remote);
      remote = INVALID_SOCKET;
    }
    if (!ok) { ++failures_; if (socks) socksReply(client, 1); else httpReply(client, 502); return; }
    SocketBudget destinationBudget(remote, config_.handshakeTimeoutMs);
    DWORD setupTimeout = 10000;
    setsockopt(remote, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&setupTimeout), sizeof(setupTimeout));
    setsockopt(remote, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&setupTimeout), sizeof(setupTimeout));
    std::string encoded = jsonEscape(host);
    ok = !encoded.empty() && writeFrame(ssl, "{\"host\":\"" + encoded + "\",\"port\":" + std::to_string(port) + "}") && responseOK(ssl);
    if (ok && !socks && !http.connect) ok = sslWrite(ssl, http.initialData.data(), http.initialData.size());
    destinationBudget.cancel();
    if (ok) {
      if (socks) socksReply(client, 0);
      else if (http.connect) httpReply(client, 200);
      DWORD timeout = 120000;
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(remote, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(remote, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      relay(client, remote, ssl);
    } else { ++failures_; if (socks) socksReply(client, 1); else httpReply(client, 502); }
    if (ssl) SSL_free(ssl);
    { std::lock_guard<std::mutex> lock(mu_); sockets_.erase(remote); }
    closesocket(remote);
  }

  void relay(SOCKET local, SOCKET remote, SSL* ssl) {
    bool localOpen = true, remoteOpen = true;
    char buffer[16384];
    auto lastActivity = ConnectClock::now();
    while (running_ && (localOpen || remoteOpen)) {
      if (ConnectClock::now() - lastActivity >= std::chrono::milliseconds(config_.idleTimeoutMs)) break;
      fd_set readable; FD_ZERO(&readable);
      if (localOpen) FD_SET(local, &readable);
      if (remoteOpen) FD_SET(remote, &readable);
      timeval timeout{0, 100000};
      if (select(0, &readable, nullptr, nullptr, &timeout) == SOCKET_ERROR) break;
      if (localOpen && FD_ISSET(local, &readable)) {
        int n = recv(local, buffer, sizeof(buffer), 0);
        if (n > 0) {
          if (!sslWrite(ssl, buffer, n)) break;
          sent_ += n; lastActivity = ConnectClock::now();
        }
        else { localOpen = false; SSL_shutdown(ssl); }
      }
      if (remoteOpen && (FD_ISSET(remote, &readable) || SSL_pending(ssl) > 0)) {
        int n = SSL_read(ssl, buffer, sizeof(buffer));
        if (n > 0) {
          if (!socketWrite(local, buffer, n)) break;
          received_ += n; lastActivity = ConnectClock::now();
        }
        else { remoteOpen = false; shutdown(local, SD_SEND); }
      }
    }
  }

  Config config_;
  SSL_CTX* ctx_ = nullptr;
  std::atomic<SOCKET> listener_{INVALID_SOCKET};
  std::atomic<bool> running_{false};
  std::atomic<int> sessions_{0};
  std::atomic<uint64_t> sent_{0}, received_{0}, failures_{0};
  std::thread acceptThread_;
  std::mutex mu_;
  std::condition_variable drained_;
  std::set<SOCKET> sockets_;
};

static Service service;
static NOTIFYICONDATAW tray{};
static Config config;
static std::thread stopThread;
static bool stopping = false;
static bool exitAfterStop = false;

static DesktopUi desktop;
static DesktopForm form;
static std::string uiError;

static std::wstring wide(const char* value) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
  if (n <= 0) return {};
  std::wstring result(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, result.data(), n);
  result.pop_back(); return result;
}

static void loadForm() {
  const auto copy = [](auto& to, const std::wstring& value) {
    const auto encoded = utf8(value);
    std::copy_n(encoded.c_str(), std::min(encoded.size(), to.size() - 1), to.data());
  };
  copy(form.server, config.server); copy(form.backup, config.fallbackServer); copy(form.ca, config.caFile);
  form.remotePort = config.serverPort; form.backupPort = config.fallbackPort;
  form.localPort = config.localPort; form.timeout = config.connectTimeoutMs;
  form.savedToken = !config.protectedToken.empty();
  form.savedBackupToken = !config.fallbackProtectedToken.empty();
}

static void updateStatus(HWND) {
  wcscpy_s(tray.szTip, stopping ? L"ETL - stopping" : service.running() ? L"ETL - proxy active" : L"ETL - off");
  Shell_NotifyIconW(NIM_MODIFY, &tray);
}

static void beginStop(HWND window, bool exit) {
  if (stopping) { exitAfterStop |= exit; return; }
  if (!service.running()) { if (exit) DestroyWindow(window); return; }
  stopping = true; exitAfterStop = exit; updateStatus(window);
  stopThread = std::thread([window] {
    service.stop(); PostMessageW(window, WM_SERVICE_STOPPED, 0, 0);
  });
}

static void connectOrStop(HWND window) {
  if (stopping) return;
  if (service.running()) { beginStop(window, false); return; }
  Config next = config;
  next.server = wide(form.server.data()); next.fallbackServer = wide(form.backup.data());
  next.serverPort = form.remotePort; next.fallbackPort = form.backupPort;
  next.localPort = form.localPort; next.connectTimeoutMs = form.timeout; next.caFile = wide(form.ca.data());
  if (next.server.empty() || next.serverPort < 1 || next.serverPort > 65535 ||
      next.localPort < 1 || next.localPort > 65535 || next.fallbackPort < 1 || next.fallbackPort > 65535 ||
      next.connectTimeoutMs < 1 || next.connectTimeoutMs > 60000) {
    uiError = "Check host, ports and timeout."; return;
  }
  if (form.token[0] && !protectToken(form.token.data(), next.protectedToken)) {
    uiError = "Token: use 64 lowercase hex characters."; return;
  }
  if (form.backupToken[0] && !protectToken(form.backupToken.data(), next.fallbackProtectedToken)) {
    uiError = "Backup token: use 64 lowercase hex characters."; return;
  }
  if (next.fallbackServer.empty()) next.fallbackProtectedToken.clear();
  next.tokenFile.clear(); next.fallbackTokenFile.clear();
  std::wstring error;
  if (!service.start(next, error)) { uiError = utf8(error); return; }
  config = next;
  SecureZeroMemory(form.token.data(), form.token.size());
  SecureZeroMemory(form.backupToken.data(), form.backupToken.size());
  form.savedToken = !config.protectedToken.empty(); form.savedBackupToken = !config.fallbackProtectedToken.empty();
  uiError = saveConfig(config) ? "" : "Proxy active. Settings could not be saved.";
  updateStatus(window);
}

static void showWindow(HWND window) {
  ShowWindow(window, IsIconic(window) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(window);
}

static LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  if (desktop.message(window, message, wparam, lparam)) return 1;
  switch (message) {
    case WM_CREATE:
      tray.cbSize = sizeof(tray); tray.hWnd = window; tray.uID = 1;
      tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; tray.uCallbackMessage = WM_TRAY;
      tray.hIcon = LoadIconW(nullptr, IDI_INFORMATION);
      wcscpy_s(tray.szTip, L"ETL - off");
      Shell_NotifyIconW(NIM_ADD, &tray);
      SetTimer(window, 1, 1000, nullptr); return 0;
    case WM_SIZE:
      if (wparam != SIZE_MINIMIZED) desktop.resize(LOWORD(lparam), HIWORD(lparam));
      return 0;
    case WM_NCHITTEST: {
      POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      ScreenToClient(window, &point);
      RECT client{}; GetClientRect(window, &client);
      // Reserve the back button and window controls for normal client input.
      if (point.y >= 0 && point.y < 50 && point.x >= 54 && point.x < client.right - 90) return HTCAPTION;
      return HTCLIENT;
    }
    case WM_NCLBUTTONDBLCLK: return 0;
    case WM_COMMAND:
      if (LOWORD(wparam) == ID_CONNECT) connectOrStop(window);
      else if (LOWORD(wparam) == ID_OPEN) showWindow(window);
      else if (LOWORD(wparam) == ID_EXIT) beginStop(window, true);
      return 0;
    case WM_SERVICE_STOPPED:
      if (stopThread.joinable()) stopThread.join();
      stopping = false;
      if (exitAfterStop) DestroyWindow(window);
      else updateStatus(window);
      return 0;
    case WM_TIMER: updateStatus(window); return 0;
    case WM_TRAY:
      if (LOWORD(lparam) == WM_LBUTTONDBLCLK) showWindow(window);
      else if (LOWORD(lparam) == WM_RBUTTONUP) {
        POINT point; GetCursorPos(&point);
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, ID_OPEN, L"Open ETL");
        AppendMenuW(menu, MF_STRING | (stopping ? MF_GRAYED : 0), ID_CONNECT,
          stopping ? L"Stopping" : service.running() ? L"Disconnect" : L"Connect");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, ID_EXIT, L"Exit");
        SetForegroundWindow(window);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, window, nullptr);
        DestroyMenu(menu);
      }
      return 0;
    case WM_CLOSE: ShowWindow(window, SW_HIDE); return 0;
    case WM_DESTROY:
      KillTimer(window, 1); Shell_NotifyIconW(NIM_DELETE, &tray); PostQuitMessage(0); return 0;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) { WSACleanup(); return 1; }
  const bool previewOptions = argc == 3 && std::wstring(argv[1]) == L"--self-test-ui-options";
  const std::wstring previewPath = argc == 3 && (std::wstring(argv[1]) == L"--self-test-ui" || previewOptions) ? argv[2] : L"";
  if (argc == 2 && std::wstring(argv[1]) == L"--self-test-token-storage") {
    std::string original(64, 'a'), restored;
    std::wstring protectedValue;
    bool ok = protectToken(original, protectedValue) &&
      unprotectToken(protectedValue, restored) && restored == original;
    OPENSSL_cleanse(original.data(), original.size());
    OPENSSL_cleanse(restored.data(), restored.size());
    LocalFree(argv); WSACleanup(); return ok ? 0 : 23;
  }
  if (argc > 1 && std::wstring(argv[1]) == L"--headless") {
    if (argc % 2 != 0) { LocalFree(argv); WSACleanup(); return 22; }
    Config c;
    for (int i = 2; i + 1 < argc; i += 2) {
      std::wstring name = argv[i], value = argv[i + 1];
      if (name == L"--server") c.server = value;
      else if (name == L"--fallback-server") c.fallbackServer = value;
      else if (name == L"--fallback-token-file") c.fallbackTokenFile = value;
      else if (name == L"--token-file") c.tokenFile = value;
      else if (name == L"--ca") c.caFile = value;
      else if (name == L"--server-port") { if (!portValue(value, c.serverPort)) return 20; }
      else if (name == L"--fallback-port") { if (!portValue(value, c.fallbackPort)) return 20; }
      else if (name == L"--connect-timeout-ms") { if (!portValue(value, c.connectTimeoutMs) || c.connectTimeoutMs > 60000) return 20; }
      else if (name == L"--handshake-timeout-ms") { if (!portValue(value, c.handshakeTimeoutMs)) return 20; }
      else if (name == L"--idle-timeout-ms") {
        if (value.empty() || value.size() > 6 || !std::all_of(value.begin(), value.end(), [](wchar_t ch) { return ch >= L'0' && ch <= L'9'; })) return 20;
        c.idleTimeoutMs = std::stoi(value); if (c.idleTimeoutMs < 1 || c.idleTimeoutMs > 600000) return 20;
      }
      else if (name == L"--port") { if (!portValue(value, c.localPort)) return 21; }
      else return 22;
    }
    std::wstring error;
    int result = service.start(c, error) ? 0 : 3;
    if (!result) while (true) Sleep(1000);
    LocalFree(argv); WSACleanup(); return result;
  }
  LocalFree(argv);
  config = previewPath.empty() ? loadConfig() : Config{};
  loadForm();
  WNDCLASSW wc{}; wc.lpfnWndProc = windowProc; wc.hInstance = instance;
  wc.lpszClassName = L"ETLNativeClient"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  RegisterClassW(&wc);
  HWND window = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"ETL", WS_POPUP | WS_MINIMIZEBOX | WS_SYSMENU,
    CW_USEDEFAULT, CW_USEDEFAULT, 360, 400, nullptr, nullptr, instance, nullptr);
  if (!window) { WSACleanup(); return 1; }
  const int rounded = 2;
  const DWORD noBorder = 0xfffffffe;
  DwmSetWindowAttribute(window, static_cast<DWMWINDOWATTRIBUTE>(33), &rounded, sizeof(rounded));
  DwmSetWindowAttribute(window, static_cast<DWMWINDOWATTRIBUTE>(34), &noBorder, sizeof(noBorder));
  if (!desktop.initialize(window)) {
    MessageBoxW(window, L"DirectX 11 could not start.", L"ETL", MB_ICONERROR);
    DestroyWindow(window); WSACleanup(); return 2;
  }
  if (!previewPath.empty()) {
    if (previewOptions) desktop.showOptions();
    for (int i = 0; i < 4; ++i) desktop.render(form, DesktopState{});
    POINT drag{100, 20}, control{320, 20};
    ClientToScreen(window, &drag); ClientToScreen(window, &control);
    const bool chrome = !(GetWindowLongPtrW(window, GWL_STYLE) & WS_CAPTION) &&
      SendMessageW(window, WM_NCHITTEST, 0, MAKELPARAM(drag.x, drag.y)) == HTCAPTION &&
      SendMessageW(window, WM_NCHITTEST, 0, MAKELPARAM(control.x, control.y)) == HTCLIENT;
    const bool ok = chrome && desktop.capture(previewPath);
    desktop.shutdown(); DestroyWindow(window); WSACleanup(); return ok ? 0 : 24;
  }
  ShowWindow(window, SW_SHOW);
  MSG message{};
  bool quit = false;
  while (!quit) {
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      if (message.message == WM_QUIT) { quit = true; break; }
      TranslateMessage(&message); DispatchMessageW(&message);
    }
    if (quit) break;
    if (!IsWindowVisible(window) || IsIconic(window)) { WaitMessage(); continue; }
    DesktopState state{service.running(), stopping, service.sessions(), service.sent(), service.received(), service.failures(), uiError};
    if (desktop.render(form, state)) connectOrStop(window);
  }
  desktop.shutdown();
  SecureZeroMemory(form.token.data(), form.token.size());
  SecureZeroMemory(form.backupToken.data(), form.backupToken.size());
  if (stopThread.joinable()) stopThread.join();
  service.stop();
  WSACleanup();
  return 0;
}
