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

static bool runCommand(const std::wstring& command) {
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  // CreateProcessW may write into lpCommandLine, so it gets a private copy.
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');
  const BOOL ok = CreateProcessW(nullptr, mutableCommand.data(),
    nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  if (!ok) return false;
  WaitForSingleObject(process.hProcess, 15000);
  DWORD code = 0;
  GetExitCodeProcess(process.hProcess, &code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return code == 0;
}

// Startup checkpoint log: the VPN path runs elevated and windowless, so a
// crash leaves nothing behind unless each step writes here first.
static void checkpoint(const char* step) {
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

struct RoutePlan {
  std::string server;
  std::string gateway;
  DWORD interfaceIndex = 0;
  bool ok = false;
};

static RoutePlan planRoutes(const std::wstring& server) {
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
  if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
  std::wstring command(std::wstring(L"\"") + path + L"\" --vpn-guard " + server +
    L" " + std::to_wstring(GetCurrentProcessId()));
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return false;
  CloseHandle(process.hThread);
  guard = process.hProcess;
  return true;
}

bool Vpn::start(int localPort, const std::wstring& server, int serverPort,
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
    const RoutePlan plan = planRoutes(server);
    if (!plan.ok) { error = L"Server address or default route unavailable."; return false; }
    checkpoint("plan-ok", plan.server + " via " + (plan.gateway.empty() ? std::string("if") : plan.gateway));
    const std::wstring serverIp = widen(plan.server);
    const std::wstring gateway = widen(plan.gateway);
    HANDLE guard = nullptr;
    checkpoint("guard");
    if (!spawnGuard(serverIp, guard)) {
      error = L"Restoration guard could not be armed."; return false;
    }
    guard_ = guard;
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
      error = L"Server host route could not be installed."; return false;
    }
    serverRoute_ = serverIp;
    checkpoint("job");
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
      runCommand(L"route delete " + serverIp);
      error = L"Job object failed.";
      return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    const std::wstring command = L"\"" + (directory / L"hev-socks5-tunnel.exe").wstring() +
      L"\" \"" + config.wstring() + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    checkpoint("spawn");
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &process)) {
      CloseHandle(job);
      runCommand(L"route delete " + serverIp);
      error = L"TUN engine could not start.";
      return false;
    }
    AssignProcessToJobObject(job, process.hProcess);
    CloseHandle(process.hThread);
    checkpoint("adapter-wait");
    const DWORD adapter = waitForAdapter(kAdapterName, "198.18.0.1", 20);
    if (!adapter) {
      checkpoint("adapter-timeout");
      TerminateJobObject(job, 1);
      CloseHandle(process.hProcess);
      CloseHandle(job);
      runCommand(L"route delete " + serverIp);
      error = L"TUN adapter did not come up.";
      return false;
    }
    checkpoint("dns", std::to_string(adapter));
    runCommand(L"netsh interface ip set dns name=\"" + std::wstring(kAdapterName) +
      L"\" static " + kTunDns + L" validate=no");
    if (!scope.empty()) {
      checkpoint("scoped-route");
      if (!runCommand(L"route add " + scope + L" mask 255.255.255.255 " + kTunAddress +
          L" metric 1 if " + std::to_wstring(adapter))) {
        stop();
        error = L"Scoped route could not be installed.";
        return false;
      }
      scopeRoute_ = scope;
    }
    job_ = job;
    process_ = process.hProcess;
    checkpoint("started");
    return true;
  } catch (...) {
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
  if (!job_) { stopGuard(guard_); return; }
  HANDLE job = static_cast<HANDLE>(job_);
  HANDLE process = static_cast<HANDLE>(process_);
  job_ = nullptr;
  process_ = nullptr;
  if (!scopeRoute_.empty()) {
    runCommand(L"route delete " + scopeRoute_);
    scopeRoute_.clear();
  }
  // Killing the job removes the adapter, and Windows drops its routes with it.
  TerminateJobObject(job, 1);
  if (process) CloseHandle(process);
  CloseHandle(job);
  if (!serverRoute_.empty()) {
    runCommand(L"route delete " + serverRoute_);
    serverRoute_.clear();
  }
  stopGuard(guard_);
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
