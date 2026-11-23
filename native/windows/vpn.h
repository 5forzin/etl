#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

// VPN mode orchestration: the embedded hev-socks5-tunnel runtime provides the
// TUN device and lwIP; this module owns extraction, spawning, routing, DNS and
// the restoration guarantees (dead-man switch) around it.
namespace etlvpn {

struct VpnStatus {
  bool active = false;
  std::wstring detail;
};

// One health check. Only `tunnel` can cause a disconnect: it proves the routes
// still point at the adapter and that a DNS exchange crossed the TUN, the local
// SOCKS bridge and an authenticated ETL session. `dns` reports whether the
// engine's mapped-DNS answered over UDP. Other VPNs and firewalls commonly
// block all UDP port 53 outside their own adapter, which leaves the tunnel
// healthy while system DNS cannot use it, so `dns` is informational.
struct HealthReport {
  bool tunnel = false;
  bool dns = false;
};

// Decides when failed checks justify restoring the normal connection. A single
// slow relay (a new ETL session takes about two seconds on a slow network) must
// not tear the tunnel down, so it takes several consecutive tunnel failures.
class TunnelWatch {
 public:
  using Clock = std::chrono::steady_clock;
  static constexpr int kFailureLimit = 3;
  static constexpr std::chrono::seconds kStartupGrace{3};
  static constexpr std::chrono::seconds kHealthyInterval{4};
  static constexpr std::chrono::seconds kRetryInterval{2};

  explicit TunnelWatch(Clock::time_point started) : next_(started + kStartupGrace) {}
  bool due(Clock::time_point now) const { return now >= next_; }
  // Returns false once the tunnel must be torn down.
  bool record(const HealthReport& report, Clock::time_point now) {
    dnsViaTunnel_ = report.dns;
    failures_ = report.tunnel ? 0 : failures_ + 1;
    next_ = now + (report.tunnel ? kHealthyInterval : kRetryInterval);
    return failures_ < kFailureLimit;
  }
  bool dnsViaTunnel() const { return dnsViaTunnel_; }
  int failures() const { return failures_; }

 private:
  Clock::time_point next_;
  int failures_ = 0;
  bool dnsViaTunnel_ = true;  // unknown until the first check; never warn early
};

struct RoutePlan {
  std::string server;
  std::string gateway;
  unsigned long interfaceIndex = 0;
  bool ok = false;
};

RoutePlan planRoutes(const std::wstring& server);
void checkpoint(const char* step);

// Selective mode routes only the destinations that listed applications cannot
// reach directly. Twingate opens its relay connections on TCP ports that
// restrictive networks drop; such an attempt sits in SYN-SENT, and routing its
// /32 into the tunnel lets the next SYN retransmission through ETL.
// Pure filter (addresses in network byte order, as in MIB_TCPROW).
bool publicIpv4(uint32_t address);
bool selectiveApp(const std::wstring& imageName);
bool selectiveDestination(unsigned long tcpState, uint32_t remote, uint16_t remotePort, uint32_t server);
bool selectiveCandidate(const std::wstring& imageName, unsigned long tcpState,
                        uint32_t remote, uint16_t remotePort, uint32_t server);
std::string ipv4Text(uint32_t address);

class SelectiveScanner {
 public:
  static constexpr size_t kMaxDestinations = 256;
  explicit SelectiveScanner(const std::string& serverIp);
  // Destinations seen for the first time since the previous scan.
  std::vector<uint32_t> scan();
  size_t routed() const { return seen_.size(); }

 private:
  bool matches(unsigned long pid);
  uint32_t server_ = 0;
  std::set<uint32_t> seen_;
  // pid -> (checked at, matches); pids are reused, so entries expire.
  std::map<unsigned long, std::pair<unsigned long long, bool>> processes_;
};

enum class VpnLayout {
  Full,       // default routes, mapped DNS, IPv6 half-defaults
  Scoped,     // one fixed /32 (headless tests)
  Selective,  // /32 routes added at runtime through routeDestination()
};

class Vpn {
 public:
  // A scope installs only its /32 and leaves DNS alone. Empty scope routes
  // IPv4 and IPv6 through the TUN and pairs mapdns with its fake-IP route.
  // Scoped requires `scope`; the other layouts require it empty.
  bool start(int localPort, const RoutePlan& plan, VpnLayout layout,
             const std::wstring& scope, std::wstring& error);
  void stop();
  // Selective layout only: send one more destination (network byte order)
  // through the tunnel. Returns false if it is not routable or already routed.
  bool routeDestination(uint32_t address);
  // Returns true on engine exit or wait failure; logs the reason for teardown.
  bool waitEngine(unsigned long timeoutMs) const;
  HealthReport health() const;
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
  mutable int dnsState_ = -1;   // last mapped-DNS result, so transitions are logged once
  VpnLayout layout_ = VpnLayout::Full;
  unsigned long selectiveAdapter_ = 0;
  std::vector<std::wstring> selectiveRoutes_;
  unsigned long physicalWeakHost_ = 0;  // interface whose weak host send to restore
};

bool extractRuntime(const std::filesystem::path& directory, std::wstring& error);
bool isElevated();
std::filesystem::path runtimeDirectory();
int runGuard(const std::wstring& server, unsigned long parentPid,
             const std::wstring& readyEvent = L"", unsigned long weakHostInterface = 0);

// Offline checks: extraction with hash verification and the routing plan.
bool selfTestExtract(std::wstring& error);
std::string selfTestPlan(const std::wstring& server, int serverPort);

// Checks a bounded DNS exchange over TCP, including the returned message ID.
bool probeDnsTcp(const char* address, unsigned short port, unsigned long timeoutMs);

}  // namespace etlvpn
