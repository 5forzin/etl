#pragma once
#include <filesystem>
#include <string>

// VPN mode orchestration: the embedded hev-socks5-tunnel runtime provides the
// TUN device and lwIP; this module owns extraction, spawning, routing, DNS and
// the restoration guarantees (dead-man switch) around it.
namespace etlvpn {

struct VpnStatus {
  bool active = false;
  std::wstring detail;
};

struct RoutePlan {
  std::string server;
  std::string gateway;
  unsigned long interfaceIndex = 0;
  bool ok = false;
};

RoutePlan planRoutes(const std::wstring& server);
void checkpoint(const char* step);

class Vpn {
 public:
  // A scope installs only its /32 and leaves DNS alone. Empty scope routes
  // IPv4 and IPv6 through the TUN and pairs mapdns with its fake-IP route.
  bool start(int localPort, const RoutePlan& plan,
             const std::wstring& scope, std::wstring& error);
  void stop();
  // Returns true on engine exit or wait failure; logs the reason for teardown.
  bool waitEngine(unsigned long timeoutMs) const;
  VpnStatus status() const;
  ~Vpn() { stop(); }

 private:
  void* job_ = nullptr;         // HANDLE, kills the engine with this process
  void* process_ = nullptr;     // HANDLE of hev-socks5-tunnel.exe
  void* guard_ = nullptr;       // HANDLE of the --vpn-guard watchdog copy
  std::wstring serverRoute_;    // host route to remove on stop
  std::wstring scopeRoute_;     // scoped test route to remove on stop
  bool mapDnsRoute_ = false;
  unsigned long fullAdapter_ = 0;
  bool defaultRoutes_[2]{};
  bool ipv6Routes_[2]{};
};

bool extractRuntime(const std::filesystem::path& directory, std::wstring& error);
bool isElevated();
std::filesystem::path runtimeDirectory();
int runGuard(const std::wstring& server, unsigned long parentPid,
             const std::wstring& readyEvent = L"");

// Offline checks: extraction with hash verification and the routing plan.
bool selfTestExtract(std::wstring& error);
std::string selfTestPlan(const std::wstring& server, int serverPort);

}  // namespace etlvpn
