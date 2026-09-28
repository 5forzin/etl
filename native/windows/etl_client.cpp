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
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

constexpr UINT WM_TRAY = WM_APP + 1;
constexpr UINT WM_SERVICE_STOPPED = WM_APP + 2;
constexpr int ID_CONNECT = 101;
constexpr int ID_SERVER = 102;
constexpr int ID_SERVER_PORT = 103;
constexpr int ID_TOKEN = 104;
constexpr int ID_LOCAL_PORT = 105;
constexpr int ID_CA = 106;
constexpr int ID_STATUS = 107;
constexpr int ID_OPEN = 201;
constexpr int ID_EXIT = 202;

struct Config {
  std::wstring server = L"etl.nora.systems";
  int serverPort = 443;
  std::wstring tokenFile;
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

static Config loadConfig() {
  Config c;
  auto path = configPath();
  c.server = readSetting(path, L"server", c.server.c_str());
  c.tokenFile = readSetting(path, L"token_file", L"");
  c.caFile = readSetting(path, L"ca_file", L"");
  int value;
  if (portValue(readSetting(path, L"server_port", L"443"), value)) c.serverPort = value;
  if (portValue(readSetting(path, L"local_port", L"1080"), value)) c.localPort = value;
  return c;
}

static void saveConfig(const Config& c) {
  auto path = configPath();
  WritePrivateProfileStringW(L"client", L"server", c.server.c_str(), path.c_str());
  WritePrivateProfileStringW(L"client", L"server_port", std::to_wstring(c.serverPort).c_str(), path.c_str());
  WritePrivateProfileStringW(L"client", L"token_file", c.tokenFile.c_str(), path.c_str());
  WritePrivateProfileStringW(L"client", L"local_port", std::to_wstring(c.localPort).c_str(), path.c_str());
  WritePrivateProfileStringW(L"client", L"ca_file", c.caFile.c_str(), path.c_str());
}

static bool readToken(const std::wstring& path, std::string& token) {
  std::ifstream file(std::filesystem::path(path), std::ios::binary);
  if (!file) return false;
  file.seekg(0, std::ios::end);
  if (file.tellg() > 256) return false;
  file.seekg(0);
  token.assign(std::istreambuf_iterator<char>(file), {});
  while (!token.empty() && (token.back() == '\n' || token.back() == '\r' || token.back() == ' ')) token.pop_back();
  return token.size() == 64 && std::all_of(token.begin(), token.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
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
  unsigned char header[4];
  if (!socketRead(s, header, 2, running) || header[0] != 5 || header[1] == 0) return false;
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

static SOCKET connectServer(const std::string& host, int port, const std::atomic<bool>& running) {
  if (!running) return INVALID_SOCKET;
  addrinfo hint{}; hint.ai_socktype = SOCK_STREAM; hint.ai_protocol = IPPROTO_TCP;
  addrinfo* addresses = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hint, &addresses)) return INVALID_SOCKET;
  // Keep the OS-preferred family first, but give the other family a prompt try.
  std::vector<addrinfo*> preferred, alternate, order;
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

  using Clock = std::chrono::steady_clock;
  constexpr auto delay = std::chrono::milliseconds(250);
  constexpr auto poll = std::chrono::milliseconds(100);
  const auto deadline = Clock::now() + std::chrono::seconds(10);
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
  freeaddrinfo(addresses);
  if (result != INVALID_SOCKET) {
    u_long nonblocking = 0;
    if (ioctlsocket(result, FIONBIO, &nonblocking) != 0 || !running) {
      closesocket(result);
      return INVALID_SOCKET;
    }
    DWORD timeout = 10000;
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
    if (!readToken(config.tokenFile, token)) { error = L"Selecione um arquivo de token válido (64 caracteres hexadecimais)."; return false; }
    OPENSSL_cleanse(token.data(), token.size());
    if (config.server.empty() || config.serverPort < 1 || config.localPort < 1) { error = L"Configuração inválida."; return false; }
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) { error = L"Não foi possível iniciar o TLS."; return false; }
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx_);
    addWindowsTrust(ctx_);
    if (!config.caFile.empty() && SSL_CTX_load_verify_file(ctx_, utf8(config.caFile).c_str()) != 1) {
      error = L"Arquivo CA inválido."; SSL_CTX_free(ctx_); ctx_ = nullptr; return false;
    }
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { error = L"Não foi possível criar o listener local."; SSL_CTX_free(ctx_); ctx_ = nullptr; return false; }
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(config.localPort);
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(listener, SOMAXCONN)) {
      error = L"Porta local ocupada ou indisponível."; closesocket(listener); SSL_CTX_free(ctx_); ctx_ = nullptr; return false;
    }
    config_ = config; listener_ = listener; running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    return true;
  }

  void stop() {
    if (!running_.exchange(false)) return;
    SOCKET listener = listener_.exchange(INVALID_SOCKET);
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (acceptThread_.joinable()) acceptThread_.join();
    std::vector<SOCKET> live;
    { std::lock_guard<std::mutex> lock(mu_); live.assign(sockets_.begin(), sockets_.end()); }
    for (SOCKET s : live) shutdown(s, SD_BOTH);
    std::unique_lock<std::mutex> lock(mu_);
    drained_.wait(lock, [this] { return sessions_ == 0; });
    lock.unlock();
    SSL_CTX_free(ctx_); ctx_ = nullptr;
  }

  bool running() const { return running_; }
  int sessions() const { return sessions_; }

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
      std::thread([this, client] {
        process(client);
        {
          std::lock_guard<std::mutex> lock(mu_);
          sockets_.erase(client);
          closesocket(client);
          --sessions_;
        }
        drained_.notify_all();
      }).detach();
    }
  }

  void process(SOCKET client) {
    std::string host;
    int port = 0;
    if (!socksRequest(client, host, port, running_) || !running_) return;
    SOCKET remote = connectServer(utf8(config_.server), config_.serverPort, running_);
    if (remote == INVALID_SOCKET) { socksReply(client, 1); return; }
    if (!running_) { closesocket(remote); return; }
    { std::lock_guard<std::mutex> lock(mu_); sockets_.insert(remote); }
    SSL* ssl = SSL_new(ctx_);
    bool ok = false;
    if (ssl) {
      std::string server = utf8(config_.server);
      if (SSL_set_fd(ssl, static_cast<int>(remote)) == 1 &&
          SSL_set_tlsext_host_name(ssl, server.c_str()) == 1 &&
          SSL_set1_host(ssl, server.c_str()) == 1 &&
          SSL_connect(ssl) == 1 && SSL_get_verify_result(ssl) == X509_V_OK) {
        std::string token;
        if (readToken(config_.tokenFile, token)) {
          ok = writeFrame(ssl, "{\"v\":1,\"token\":\"" + token + "\"}");
          OPENSSL_cleanse(token.data(), token.size());
          ok = ok && responseOK(ssl);
          std::string encoded = jsonEscape(host);
          ok = ok && !encoded.empty() && writeFrame(ssl, "{\"host\":\"" + encoded + "\",\"port\":" + std::to_string(port) + "}") && responseOK(ssl);
        }
      }
    }
    if (ok) {
      socksReply(client, 0);
      DWORD timeout = 120000;
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(remote, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      setsockopt(remote, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      relay(client, remote, ssl);
    } else socksReply(client, 1);
    if (ssl) SSL_free(ssl);
    { std::lock_guard<std::mutex> lock(mu_); sockets_.erase(remote); }
    closesocket(remote);
  }

  void relay(SOCKET local, SOCKET remote, SSL* ssl) {
    bool localOpen = true, remoteOpen = true;
    char buffer[16384];
    while (running_ && (localOpen || remoteOpen)) {
      fd_set readable; FD_ZERO(&readable);
      if (localOpen) FD_SET(local, &readable);
      if (remoteOpen) FD_SET(remote, &readable);
      timeval timeout{1, 0};
      if (select(0, &readable, nullptr, nullptr, &timeout) == SOCKET_ERROR) break;
      if (localOpen && FD_ISSET(local, &readable)) {
        int n = recv(local, buffer, sizeof(buffer), 0);
        if (n > 0) { if (!sslWrite(ssl, buffer, n)) break; }
        else { localOpen = false; SSL_shutdown(ssl); }
      }
      if (remoteOpen && (FD_ISSET(remote, &readable) || SSL_pending(ssl) > 0)) {
        int n = SSL_read(ssl, buffer, sizeof(buffer));
        if (n > 0) { if (!socketWrite(local, buffer, n)) break; }
        else { remoteOpen = false; shutdown(local, SD_SEND); }
      }
    }
  }

  Config config_;
  SSL_CTX* ctx_ = nullptr;
  std::atomic<SOCKET> listener_{INVALID_SOCKET};
  std::atomic<bool> running_{false};
  std::atomic<int> sessions_{0};
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

static std::wstring field(HWND window, int id) {
  wchar_t buffer[1024]{};
  GetWindowTextW(GetDlgItem(window, id), buffer, 1024);
  return buffer;
}

static void updateStatus(HWND window) {
  std::wstring status = stopping ? L"Desconectando..." : service.running() ? L"Ativo em 127.0.0.1:" + std::to_wstring(config.localPort) +
    L" | conexões: " + std::to_wstring(service.sessions()) : L"Desconectado";
  SetWindowTextW(GetDlgItem(window, ID_STATUS), status.c_str());
  SetWindowTextW(GetDlgItem(window, ID_CONNECT), stopping ? L"Desconectando..." : service.running() ? L"Desconectar" : L"Conectar");
  EnableWindow(GetDlgItem(window, ID_CONNECT), !stopping);
  wcscpy_s(tray.szTip, L"ETL - ");
  wcsncat_s(tray.szTip, stopping ? L"desconectando" : service.running() ? L"ativo" : L"desconectado", _TRUNCATE);
  Shell_NotifyIconW(NIM_MODIFY, &tray);
}

static void beginStop(HWND window, bool exit) {
  if (stopping) { exitAfterStop |= exit; return; }
  if (!service.running()) { if (exit) DestroyWindow(window); return; }
  stopping = true;
  exitAfterStop = exit;
  updateStatus(window);
  stopThread = std::thread([window] {
    service.stop();
    PostMessageW(window, WM_SERVICE_STOPPED, 0, 0);
  });
}

static void connectOrStop(HWND window) {
  if (stopping) return;
  if (service.running()) { beginStop(window, false); return; }
  {
    Config next;
    next.server = field(window, ID_SERVER);
    next.tokenFile = field(window, ID_TOKEN);
    next.caFile = field(window, ID_CA);
    if (!portValue(field(window, ID_SERVER_PORT), next.serverPort) ||
        !portValue(field(window, ID_LOCAL_PORT), next.localPort)) {
      MessageBoxW(window, L"Porta inválida.", L"ETL", MB_ICONERROR); return;
    }
    std::wstring error;
    if (!service.start(next, error)) { MessageBoxW(window, error.c_str(), L"ETL", MB_ICONERROR); return; }
    config = next;
    saveConfig(config);
  }
  updateStatus(window);
}

static void showWindow(HWND window) {
  ShowWindow(window, SW_SHOW);
  SetForegroundWindow(window);
}

static void label(HWND window, int y, const wchar_t* text, int editId, const std::wstring& value) {
  CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, 16, y, 105, 22, window, nullptr, nullptr, nullptr);
  CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", value.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
    125, y - 2, 280, 25, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(editId)), nullptr, nullptr);
}

static LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  switch (message) {
    case WM_CREATE:
      label(window, 20, L"Servidor", ID_SERVER, config.server);
      label(window, 55, L"Porta remota", ID_SERVER_PORT, std::to_wstring(config.serverPort));
      label(window, 90, L"Arquivo token", ID_TOKEN, config.tokenFile);
      label(window, 125, L"Porta local", ID_LOCAL_PORT, std::to_wstring(config.localPort));
      label(window, 160, L"CA opcional", ID_CA, config.caFile);
      CreateWindowW(L"BUTTON", L"Conectar", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        125, 202, 130, 32, window, reinterpret_cast<HMENU>(ID_CONNECT), nullptr, nullptr);
      CreateWindowW(L"STATIC", L"Desconectado", WS_CHILD | WS_VISIBLE,
        16, 248, 380, 24, window, reinterpret_cast<HMENU>(ID_STATUS), nullptr, nullptr);
      tray.cbSize = sizeof(tray); tray.hWnd = window; tray.uID = 1;
      tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; tray.uCallbackMessage = WM_TRAY;
      tray.hIcon = LoadIconW(nullptr, IDI_INFORMATION);
      wcscpy_s(tray.szTip, L"ETL - desconectado");
      Shell_NotifyIconW(NIM_ADD, &tray);
      SetTimer(window, 1, 1000, nullptr);
      return 0;
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
        AppendMenuW(menu, MF_STRING, ID_OPEN, L"Abrir ETL");
        AppendMenuW(menu, MF_STRING | (stopping ? MF_GRAYED : 0), ID_CONNECT,
          stopping ? L"Desconectando..." : service.running() ? L"Desconectar" : L"Conectar");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, ID_EXIT, L"Sair");
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
  if (argc > 1 && std::wstring(argv[1]) == L"--headless") {
    Config c;
    for (int i = 2; i + 1 < argc; i += 2) {
      std::wstring name = argv[i], value = argv[i + 1];
      if (name == L"--server") c.server = value;
      else if (name == L"--token-file") c.tokenFile = value;
      else if (name == L"--ca") c.caFile = value;
      else if (name == L"--server-port") { if (!portValue(value, c.serverPort)) return 20; }
      else if (name == L"--port") { if (!portValue(value, c.localPort)) return 21; }
      else return 22;
    }
    std::wstring error;
    int result = service.start(c, error) ? 0 : 3;
    if (!result) while (true) Sleep(1000);
    LocalFree(argv); WSACleanup(); return result;
  }
  LocalFree(argv);
  config = loadConfig();
  WNDCLASSW wc{}; wc.lpfnWndProc = windowProc; wc.hInstance = instance;
  wc.lpszClassName = L"ETLNativeClient"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  RegisterClassW(&wc);
  HWND window = CreateWindowExW(0, wc.lpszClassName, L"ETL | Cliente", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
    CW_USEDEFAULT, CW_USEDEFAULT, 440, 315, nullptr, nullptr, instance, nullptr);
  if (!window) { WSACleanup(); return 1; }
  std::wstring error;
  if (service.start(config, error)) updateStatus(window);
  MSG message;
  while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
  if (stopThread.joinable()) stopThread.join();
  service.stop();
  WSACleanup();
  return 0;
}
