#include "vpn.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include "resources.h"

// Same pins as the CMake download: the runtime is only ever extracted from
// resources that the build already verified against these digests.
static const char* const kComponentHashes[] = {
  "0e4274ee9e1b30e180d7df10bf244586234e0cf196650d3fcb51320b6e2bf5f9",
  "1410599ee2efcede0869abec8910398d688755952e59cf7983b15cac6de78201",
  "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
};
static const wchar_t* const kComponentNames[] = {L"hev-socks5-tunnel.exe",
  L"msys-2.0.dll", L"wintun.dll"};
static const int kComponentIds[] = {IDR_HEV_EXE, IDR_MSYS_DLL, IDR_WINTUN_DLL};
static const wchar_t kAdapterName[] = L"ETL";
static const wchar_t kTunAddress[] = L"198.18.0.1";
static const wchar_t kTunDns[] = L"198.18.0.2";
static const wchar_t* const kHalfDefaults[] = {L"0.0.0.0", L"128.0.0.0"};
static const wchar_t* const kIpv6HalfDefaults[] = {L"::/1", L"8000::/1"};

using ProbeClock = std::chrono::steady_clock;

static std::vector<unsigned char> dnsQuery() {
  const unsigned short id = static_cast<unsigned short>(GetTickCount64());
  return {static_cast<unsigned char>(id >> 8), static_cast<unsigned char>(id),
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
}

static bool waitSocket(SOCKET socket, bool write, ProbeClock::time_point deadline) {
  const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
    deadline - ProbeClock::now()).count();
  if (remaining <= 0) return false;
  fd_set ready;
  FD_ZERO(&ready); FD_SET(socket, &ready);
  timeval timeout{static_cast<long>(remaining / 1000000),
    static_cast<long>(remaining % 1000000)};
  return select(0, write ? nullptr : &ready, write ? &ready : nullptr,
    nullptr, &timeout) > 0;
}

static bool validDnsResponse(const unsigned char* bytes, size_t size,
                             const std::vector<unsigned char>& query) {
  return size >= 12 && bytes[0] == query[0] && bytes[1] == query[1] &&
    (bytes[2] & 0xf8) == 0x80 && (bytes[3] & 0x0f) == 0 &&
    (bytes[6] != 0 || bytes[7] != 0);
}

static bool probeMappedDns() {
  SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket == INVALID_SOCKET) return false;
  sockaddr_in destination{};
  destination.sin_family = AF_INET;
  destination.sin_port = htons(53);
  InetPtonA(AF_INET, "198.18.0.2", &destination.sin_addr);
  const auto query = dnsQuery();
  const auto deadline = ProbeClock::now() + std::chrono::seconds(1);
  bool ok = connect(socket, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == 0 &&
    send(socket, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0) ==
      static_cast<int>(query.size()) && waitSocket(socket, false, deadline);
  if (ok) {
    unsigned char response[512];
    const int received = recv(socket, reinterpret_cast<char*>(response), sizeof(response), 0);
    ok = received > 0 && validDnsResponse(response, static_cast<size_t>(received), query);
  }
  closesocket(socket);
  return ok;
}

static std::wstring widen(const std::string& value) {
  if (value.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
  std::wstring out(static_cast<size_t>(n - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), n);
  return out;
}

static std::string sha256(const void* data, size_t size) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return {};
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, data, size) == 1 &&
            EVP_DigestFinal_ex(ctx, digest, nullptr) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok) return {};
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char byte : digest) {
    out += hex[byte >> 4];
    out += hex[byte & 0xf];
  }
  return out;
}

namespace etlvpn {

bool probeDnsTcp(const char* address, unsigned short port, unsigned long timeoutMs) {
  SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == INVALID_SOCKET) return false;
  const auto deadline = ProbeClock::now() + std::chrono::milliseconds(timeoutMs);
  sockaddr_in destination{};
  destination.sin_family = AF_INET;
  destination.sin_port = htons(port);
  u_long nonblocking = 1;
  bool ok = InetPtonA(AF_INET, address, &destination.sin_addr) == 1 &&
    ioctlsocket(socket, FIONBIO, &nonblocking) == 0;
  if (ok && connect(socket, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) != 0)
    ok = WSAGetLastError() == WSAEWOULDBLOCK && waitSocket(socket, true, deadline);
  int error = 1, size = sizeof(error);
  ok = ok && getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == 0 && error == 0;
  const auto query = dnsQuery();
  std::vector<unsigned char> request{0, static_cast<unsigned char>(query.size())};
  request.insert(request.end(), query.begin(), query.end());
  size_t offset = 0;
  while (ok && offset < request.size()) {
    ok = waitSocket(socket, true, deadline);
    if (!ok) break;
    const int sent = send(socket, reinterpret_cast<const char*>(request.data() + offset),
      static_cast<int>(request.size() - offset), 0);
    if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
    if (sent <= 0) { ok = false; break; }
    offset += static_cast<size_t>(sent);
  }
  // The length prefix and DNS header prove that payload crossed the TUN,
  // local SOCKS bridge and authenticated ETL session in both directions.
  unsigned char response[14]{};
  offset = 0;
  while (ok && offset < sizeof(response)) {
    ok = waitSocket(socket, false, deadline);
    if (!ok) break;
    const int received = recv(socket, reinterpret_cast<char*>(response + offset),
      static_cast<int>(sizeof(response) - offset), 0);
    if (received == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
    if (received <= 0) { ok = false; break; }
    offset += static_cast<size_t>(received);
  }
  const unsigned int length = (static_cast<unsigned int>(response[0]) << 8) | response[1];
  ok = ok && length >= 12 && length <= 4096 && validDnsResponse(response + 2, 12, query);
  closesocket(socket);
  return ok;
}

std::filesystem::path runtimeDirectory() {
  PWSTR root = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &root)))
    return L"etl-runtime";
  std::filesystem::path dir = std::filesystem::path(root) / L"ETL" / L"runtime";
  CoTaskMemFree(root);
  return dir;
}

bool isElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const bool elevated = GetTokenInformation(token, TokenElevation, &elevation,
    sizeof(elevation), &size) && elevation.TokenIsElevated;
  CloseHandle(token);
  return elevated;
}

static bool extractResource(int id, const std::filesystem::path& target,
                            const char* expected, std::wstring& error) {
  const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
  if (!resource) { error = L"Missing embedded runtime resource."; return false; }
  const DWORD size = SizeofResource(nullptr, resource);
  const HGLOBAL handle = LoadResource(nullptr, resource);
  if (!handle || !size) { error = L"Runtime resource could not be loaded."; return false; }
  const void* data = LockResource(handle);
  if (sha256(data, size) != expected) {
    error = L"Embedded runtime failed its integrity check.";
    return false;
  }
  if (std::filesystem::exists(target)) {
    std::ifstream existing(target, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(existing)), {});
    existing.close();
    if (bytes.size() == size &&
        sha256(bytes.data(), bytes.size()) == expected) return true;
  }
  std::ofstream out(target, std::ios::binary | std::ios::trunc);
  if (!out) { error = L"Runtime directory is not writable."; return false; }
  out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
  out.close();
  if (!out) { error = L"Runtime extraction failed."; return false; }
  return true;
}

bool extractRuntime(const std::filesystem::path& directory, std::wstring& error) {
  std::error_code ec;
  std::filesystem::create_directories(directory, ec);
  for (size_t i = 0; i < 3; ++i) {
    if (!extractResource(kComponentIds[i], directory / kComponentNames[i],
                         kComponentHashes[i], error)) return false;
  }
  return true;
}

static bool runCommand(const std::wstring& command, std::string* error = nullptr) {
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  // CreateProcessW may write into lpCommandLine, so it gets a private copy.
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');
  const BOOL ok = CreateProcessW(nullptr, mutableCommand.data(),
    nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  if (!ok) {
    if (error) *error = "CreateProcess failed: " + std::to_string(GetLastError());
    return false;
  }
  const DWORD wait = WaitForSingleObject(process.hProcess, 15000);
  DWORD code = 1;
  bool success = false;
  if (wait == WAIT_OBJECT_0) {
    if (!GetExitCodeProcess(process.hProcess, &code)) {
      if (error) *error = "GetExitCodeProcess failed: " + std::to_string(GetLastError());
    } else {
      success = code == 0;
      if (!success && error) *error = "exit code " + std::to_string(code);
    }
  } else {
    if (error) *error = wait == WAIT_TIMEOUT ? "command timed out" :
      "WaitForSingleObject failed: " + std::to_string(GetLastError());
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 5000);
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return success;
}

// Startup checkpoint log: the VPN path runs elevated and windowless, so a
// crash leaves nothing behind unless each step writes here first.
void checkpoint(const char* step) {
  std::ofstream out(runtimeDirectory() / L"error.log", std::ios::app);
  if (out) out << step << "\n";
}

static void checkpoint(const char* step, const std::string& detail) {
  std::ofstream out(runtimeDirectory() / L"error.log", std::ios::app);
  if (out) out << step << ": " << detail << "\n";
}

static bool writeConfig(const std::filesystem::path& path, int localPort) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out << "tunnel:\n"
      << "  name: ETL\n"
      << "  mtu: 8500\n"
      << "  ipv4: 198.18.0.1\n"
      << "  ipv6: 'fc00::1'\n"
      << "socks5:\n"
      << "  port: " << localPort << "\n"
      << "  address: 127.0.0.1\n"
      << "  udp-address: '127.0.0.1'\n"
      << "  udp: 'udp'\n"
      << "mapdns:\n"
      << "  address: 198.18.0.2\n"
      << "  port: 53\n"
      << "  network: 100.64.0.0\n"
      << "  netmask: 255.192.0.0\n"
      << "  cache-size: 10000\n"
      << "misc:\n"
      << "  log-file: hev.log\n"
      << "  log-level: warn\n";
  return static_cast<bool>(out);
}

// Wait until the engine has fully configured the adapter: routes added
// before the address assignment can be flushed by the configuration change.
static DWORD waitForAdapter(const std::wstring& name, const char* address, int seconds) {
  in_addr wanted{};
  inet_pton(AF_INET, address, &wanted);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (std::chrono::steady_clock::now() < deadline) {
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size) ==
          ERROR_BUFFER_OVERFLOW && size) {
      std::vector<unsigned char> buffer(size);
      PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
      if (GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size) == NO_ERROR) {
        for (auto adapter = adapters; adapter; adapter = adapter->Next) {
          if (!adapter->FriendlyName || name != adapter->FriendlyName) continue;
          for (auto unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            const sockaddr_in* ipv4 = reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
            if (ipv4->sin_family == AF_INET && ipv4->sin_addr.s_addr == wanted.s_addr &&
                adapter->OperStatus == IfOperStatusUp) {
              return adapter->IfIndex;
            }
          }
        }
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  return 0;
}

RoutePlan planRoutes(const std::wstring& server) {
  RoutePlan plan;
  ADDRINFOW hints{};
  hints.ai_family = AF_INET;
  PADDRINFOW result = nullptr;
  if (GetAddrInfoW(server.c_str(), nullptr, &hints, &result) || !result) return plan;
  char address[INET_ADDRSTRLEN]{};
  const sockaddr_in* ipv4 = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
  if (inet_ntop(AF_INET, &ipv4->sin_addr, address, sizeof(address))) plan.server = address;
  FreeAddrInfoW(result);
  ULONG size = 0;
  if (GetIpForwardTable(nullptr, &size, 0) != ERROR_INSUFFICIENT_BUFFER || !size) return plan;
  std::vector<unsigned char> buffer(size);
  PMIB_IPFORWARDTABLE table = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
  if (GetIpForwardTable(table, &size, 0) != NO_ERROR) return plan;
  DWORD bestMetric = static_cast<DWORD>(-1);
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const MIB_IPFORWARDROW& row = table->table[i];
    if (row.dwForwardDest != 0 || row.dwForwardMask != 0) continue;
    if (row.dwForwardMetric1 < bestMetric) {
      bestMetric = row.dwForwardMetric1;
      char next[INET_ADDRSTRLEN]{};
      if (inet_ntop(AF_INET, &row.dwForwardNextHop, next, sizeof(next)) && strcmp(next, "0.0.0.0")) {
        plan.gateway = next;
        plan.interfaceIndex = row.dwForwardIfIndex;
      }
    }
  }
  plan.ok = !plan.server.empty() && plan.interfaceIndex != 0;
  return plan;
}

// The dead-man switch is a second copy of this executable watching the
// parent process; it is deliberately NOT assigned to the engine job so a
// crash of the main client still leaves a cleaner behind.
static bool spawnGuard(const std::wstring& server, HANDLE& guard) {
  wchar_t path[MAX_PATH]{};
  const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (!length || length >= MAX_PATH) {
    checkpoint("guard-error", "Executable path unavailable or too long.");
    return false;
  }
  const std::wstring eventName = L"Local\\ETL-VpnGuard-" +
    std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
  HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
  if (!ready) {
    checkpoint("guard-error", "CreateEvent failed: " + std::to_string(GetLastError()));
    return false;
  }
  std::wstring command(std::wstring(L"\"") + path + L"\" --vpn-guard " + server +
    L" " + std::to_wstring(GetCurrentProcessId()) + L" " + eventName);
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  // Only the engine is assigned to our kill-on-close job. The guard checks
  // any remaining enclosing job's limits before signaling readiness.
  if (!CreateProcessW(path, mutableCommand.data(), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
      nullptr, nullptr, &startup, &process)) {
    checkpoint("guard-error", "CreateProcess failed: " + std::to_string(GetLastError()));
    CloseHandle(ready);
    return false;
  }
  BOOL inJob = TRUE;
  if (!IsProcessInJob(process.hProcess, nullptr, &inJob))
    checkpoint("guard-note", "IsProcessInJob failed: " + std::to_string(GetLastError()));
  else if (inJob) checkpoint("guard-in-job", "Guard will check enclosing job limits.");
  bool ok = true;
  if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    checkpoint("guard-error", "ResumeThread failed: " + std::to_string(GetLastError()));
    ok = false;
  }
  CloseHandle(process.hThread);
  if (ok) {
    HANDLE handles[]{ready, process.hProcess};
    const DWORD wait = WaitForMultipleObjects(2, handles, FALSE, 10000);
    if (wait == WAIT_FAILED)
      checkpoint("guard-error", "Readiness wait failed: " + std::to_string(GetLastError()));
    else if (wait == WAIT_TIMEOUT) checkpoint("guard-error", "Readiness wait timed out.");
    ok = wait == WAIT_OBJECT_0 && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT;
    if (!ok && (wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1)) {
      DWORD code = 0;
      if (GetExitCodeProcess(process.hProcess, &code))
        checkpoint("guard-error", "Guard exited during startup: " + std::to_string(code));
      else checkpoint("guard-error", "GetExitCodeProcess failed: " + std::to_string(GetLastError()));
    }
  }
  CloseHandle(ready);
  if (!ok) {
    TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hProcess);
    return false;
  }
  guard = process.hProcess;
  return true;
}

static void guardLog(const std::string& message) {
  std::ofstream out(runtimeDirectory() / L"guard.log", std::ios::app);
  if (out) out << message << "\n";
}

int runGuard(const std::wstring& server, unsigned long parentPid,
             const std::wstring& readyEvent) {
  guardLog("starting parent=" + std::to_string(parentPid));
  auto finish = [](int code) {
    guardLog("exiting code=" + std::to_string(code));
    // Avoid DLL-detach deadlocks in the watchdog's cleanup path.
    TerminateProcess(GetCurrentProcess(), code);
    return code;
  };
  BOOL inJob = FALSE;
  if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob)) {
    guardLog("IsProcessInJob failed: " + std::to_string(GetLastError()));
    return finish(1);
  }
  if (inJob) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    if (!QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits), nullptr)) {
      guardLog("QueryInformationJobObject failed: " + std::to_string(GetLastError()));
      return finish(1);
    }
    if (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) {
      guardLog("guard-in-job: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is unsafe.");
      return finish(1);
    }
    guardLog("guard-in-job: enclosing job has no KILL_ON_JOB_CLOSE limit.");
  }
  HANDLE watched = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
  if (!watched) {
    guardLog("OpenProcess failed: " + std::to_string(GetLastError()));
    if (!readyEvent.empty()) return finish(1);
  }
  if (!readyEvent.empty()) {
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyEvent.c_str());
    if (!ready) {
      guardLog("OpenEvent failed: " + std::to_string(GetLastError()));
      CloseHandle(watched);
      return finish(1);
    }
    guardLog("armed parent=" + std::to_string(parentPid));
    const BOOL signaled = SetEvent(ready);
    if (!signaled) guardLog("SetEvent failed: " + std::to_string(GetLastError()));
    CloseHandle(ready);
    if (!signaled) { CloseHandle(watched); return finish(1); }
  }
  if (watched) {
    if (WaitForSingleObject(watched, INFINITE) != WAIT_OBJECT_0)
      guardLog("Parent wait failed: " + std::to_string(GetLastError()));
    CloseHandle(watched);
  }
  guardLog("awake parent=" + std::to_string(parentPid));
  bool removed = false;
  for (int attempt = 1; attempt <= 2; ++attempt) {
    std::string error;
    if (runCommand(L"route delete " + server, &error)) { removed = true; break; }
    guardLog("Route delete attempt " + std::to_string(attempt) + ": " + error);
    if (attempt == 1) Sleep(250);
  }
  std::string error;
  if (!runCommand(L"ipconfig /flushdns", &error)) guardLog("DNS flush: " + error);
  return finish(removed ? 0 : 1);
}

bool Vpn::start(int localPort, const RoutePlan& plan,
                const std::wstring& scope, std::wstring& error) {
  try {
    checkpoint("start");
    if (job_) { error = L"VPN mode is already running."; return false; }
    if (!isElevated()) { error = L"VPN mode requires elevation."; return false; }
    const std::filesystem::path directory = runtimeDirectory();
    checkpoint("extract");
    if (!extractRuntime(directory, error)) return false;
    const std::filesystem::path config = directory / L"main.yml";
    checkpoint("config");
    if (!writeConfig(config, localPort)) {
      error = L"Engine configuration could not be written."; return false;
    }
    checkpoint("plan");
    if (!plan.ok) { error = L"Server address or default route unavailable."; return false; }
    checkpoint("plan-ok", plan.server + " via " + (plan.gateway.empty() ? std::string("if") : plan.gateway));
    const std::wstring serverIp = widen(plan.server);
    const std::wstring gateway = widen(plan.gateway);
    HANDLE guard = nullptr;
    if (!spawnGuard(serverIp, guard)) {
      error = L"Restoration guard could not be armed."; return false;
    }
    guard_ = guard;
    checkpoint("guard");
    // The engine must reach the ETL server outside the tunnel, so the host
    // route goes in before anything points at the adapter.
    std::wstring hostRoute(L"route add ");
    hostRoute.append(serverIp);
    hostRoute.append(L" mask 255.255.255.255 ");
    if (gateway.empty()) hostRoute.append(std::to_wstring(plan.interfaceIndex));
    else {
      hostRoute.append(gateway);
      hostRoute.append(L" if ");
      hostRoute.append(std::to_wstring(plan.interfaceIndex));
    }
    checkpoint("host-route");
    if (!runCommand(hostRoute)) {
      stop();
      error = L"Server host route could not be installed."; return false;
    }
    serverRoute_ = serverIp;
    checkpoint("job");
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
      stop();
      error = L"Job object failed.";
      return false;
    }
    job_ = job;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
      stop();
      error = L"Job object limits could not be set.";
      return false;
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    const std::wstring command = L"\"" + (directory / L"hev-socks5-tunnel.exe").wstring() +
      L"\" \"" + config.wstring() + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    checkpoint("spawn");
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, directory.c_str(), &startup, &process)) {
      stop();
      error = L"TUN engine could not start.";
      return false;
    }
    process_ = process.hProcess;
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
      TerminateProcess(process.hProcess, 1);
      CloseHandle(process.hThread);
      stop();
      error = L"TUN engine could not be assigned to its job or resumed.";
      return false;
    }
    CloseHandle(process.hThread);
    checkpoint("adapter-wait");
    const DWORD adapter = waitForAdapter(kAdapterName, "198.18.0.1", 20);
    if (!adapter) {
      checkpoint("adapter-timeout");
      stop();
      error = L"TUN adapter did not come up.";
      return false;
    }
    if (!scope.empty()) {
      // Scoped traffic must keep the physical adapter's real DNS answers.
      checkpoint("scoped-route");
      if (!runCommand(L"route add " + scope + L" mask 255.255.255.255 " + kTunAddress +
          L" metric 1 if " + std::to_wstring(adapter))) {
        stop();
        error = L"Scoped route could not be installed.";
        return false;
      }
      scopeRoute_ = scope;
    } else {
      // Full mode must route fake-IP answers before advertising mapdns.
      checkpoint("mapdns-route");
      if (!runCommand(L"route add 100.64.0.0 mask 255.192.0.0 " +
          std::wstring(kTunAddress) + L" metric 1 if " + std::to_wstring(adapter))) {
        stop();
        error = L"Mapdns route could not be installed.";
        return false;
      }
      mapDnsRoute_ = true;
      fullAdapter_ = adapter;
      // More-specific routes preserve the physical default and the server /32.
      checkpoint("default-routes");
      for (size_t i = 0; i < 2; ++i) {
        if (!runCommand(L"route add " + std::wstring(kHalfDefaults[i]) +
            L" mask 128.0.0.0 " + kTunAddress + L" metric 1 if " + std::to_wstring(adapter))) {
          stop();
          error = L"IPv4 default route could not be installed.";
          return false;
        }
        defaultRoutes_[i] = true;
      }
      checkpoint("ipv6-routes");
      for (size_t i = 0; i < 2; ++i) {
        if (!runCommand(L"netsh interface ipv6 add route prefix=" +
            std::wstring(kIpv6HalfDefaults[i]) + L" interface=\"" + kAdapterName +
            L"\" nexthop=:: metric=1 store=active")) {
          stop();
          error = L"IPv6 default route could not be installed.";
          return false;
        }
        ipv6Routes_[i] = true;
      }
      checkpoint("dns", std::to_string(adapter));
      if (!runCommand(L"netsh interface ip set dns name=\"" + std::wstring(kAdapterName) +
          L"\" static " + kTunDns + L" validate=no")) {
        stop();
        error = L"TUN DNS could not be configured.";
        return false;
      }
    }
    checkpoint("started");
    return true;
  } catch (...) {
    stop();
    error = L"VPN mode failed unexpectedly.";
    return false;
  }
}

static void stopGuard(void*& guard) {
  if (!guard) return;
  HANDLE handle = static_cast<HANDLE>(guard);
  guard = nullptr;
  // On a clean stop the watchdog is unnecessary; after a crash it has
  // already seen the parent die and cleaned up on its own.
  TerminateProcess(handle, 0);
  CloseHandle(handle);
}

void Vpn::stop() {
  if (!job_ && !process_ && !guard_ && serverRoute_.empty() &&
      scopeRoute_.empty() && !mapDnsRoute_ && !fullAdapter_) return;
  HANDLE job = static_cast<HANDLE>(job_);
  HANDLE process = static_cast<HANDLE>(process_);
  job_ = nullptr;
  process_ = nullptr;
  for (size_t i = 0; i < 2; ++i) {
    if (!defaultRoutes_[i]) continue;
    runCommand(L"route delete " + std::wstring(kHalfDefaults[i]) +
      L" mask 128.0.0.0 " + kTunAddress + L" if " + std::to_wstring(fullAdapter_));
    defaultRoutes_[i] = false;
  }
  for (size_t i = 0; i < 2; ++i) {
    if (!ipv6Routes_[i]) continue;
    runCommand(L"netsh interface ipv6 delete route prefix=" +
      std::wstring(kIpv6HalfDefaults[i]) + L" interface=\"" + kAdapterName +
      L"\" nexthop=:: store=active");
    ipv6Routes_[i] = false;
  }
  fullAdapter_ = 0;
  if (!scopeRoute_.empty()) {
    runCommand(L"route delete " + scopeRoute_);
    scopeRoute_.clear();
  }
  if (mapDnsRoute_) {
    runCommand(L"route delete 100.64.0.0 mask 255.192.0.0");
    mapDnsRoute_ = false;
  }
  // Killing the job removes the adapter, and Windows drops its routes with it.
  if (job) TerminateJobObject(job, 1);
  if (process) {
    WaitForSingleObject(process, 5000);
    CloseHandle(process);
  }
  if (job) CloseHandle(job);
  if (!serverRoute_.empty()) {
    if (!runCommand(L"route delete " + serverRoute_))
      runCommand(L"route delete " + serverRoute_);
    serverRoute_.clear();
  }
  runCommand(L"ipconfig /flushdns");
  stopGuard(guard_);
}

bool Vpn::waitEngine(unsigned long timeoutMs) const {
  if (!process_) return true;
  const DWORD wait = WaitForSingleObject(static_cast<HANDLE>(process_), timeoutMs);
  if (wait == WAIT_TIMEOUT) return false;
  if (wait == WAIT_OBJECT_0) checkpoint("engine-died");
  else checkpoint("engine-wait-error", std::to_string(GetLastError()));
  return true;
}

bool Vpn::healthy() const {
  if (!fullAdapter_) return false;
  for (const char* address : {"1.1.1.1", "142.250.0.1", "100.64.0.1"}) {
    in_addr destination{};
    InetPtonA(AF_INET, address, &destination);
    MIB_IPFORWARDROW route{};
    if (GetBestRoute(destination.s_addr, 0, &route) != NO_ERROR ||
        route.dwForwardIfIndex != fullAdapter_) {
      checkpoint("health-route-failed");
      return false;
    }
  }
  if (!probeMappedDns()) { checkpoint("health-dns-failed"); return false; }
  // Independent resolvers avoid disconnecting because one probe provider is
  // unavailable. These sockets follow the full-mode routes, never a proxy override.
  if (probeDnsTcp("1.1.1.1", 53, 2000) || probeDnsTcp("8.8.8.8", 53, 2000)) return true;
  checkpoint("health-relay-failed");
  return false;
}

VpnStatus Vpn::status() const {
  VpnStatus result;
  result.active = job_ != nullptr;
  result.detail = result.active ? L"tun up" : L"stopped";
  return result;
}

bool selfTestExtract(std::wstring& error) {
  return extractRuntime(runtimeDirectory(), error);
}

std::string selfTestPlan(const std::wstring& server, int serverPort) {
  const RoutePlan plan = planRoutes(server);
  std::ostringstream out;
  out << "{\"server\":\"" << plan.server << "\",\"port\":" << serverPort
      << ",\"gateway\":\"" << plan.gateway << "\",\"interface\":" << plan.interfaceIndex
      << ",\"tunAddress\":\"198.18.0.1\",\"ok\":" << (plan.ok ? "true" : "false") << "}";
  return out.str();
}

}  // namespace etlvpn
