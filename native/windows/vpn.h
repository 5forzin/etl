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

class Vpn {
 public:
  // scopeEmpty keeps every route change off the table: only the engine and
  // adapter come up (used by the scoped-route tests before touching defaults).
  bool start(int localPort, const std::wstring& server, int serverPort,
             const std::wstring& scope, std::wstring& error);
  void stop();
  VpnStatus status() const;
  ~Vpn() { stop(); }

 private:
  void* job_ = nullptr;         // HANDLE, kills the engine with this process
  void* process_ = nullptr;     // HANDLE of hev-socks5-tunnel.exe
  void* guard_ = nullptr;       // HANDLE of the --vpn-guard watchdog copy
  std::wstring serverRoute_;    // host route to remove on stop
  std::wstring scopeRoute_;     // scoped test route to remove on stop
  bool routed_ = false;
};

bool extractRuntime(const std::filesystem::path& directory, std::wstring& error);
bool isElevated();
std::filesystem::path runtimeDirectory();

// Offline checks: extraction with hash verification and the routing plan.
bool selfTestExtract(std::wstring& error);
std::string selfTestPlan(const std::wstring& server, int serverPort);

}  // namespace etlvpn
