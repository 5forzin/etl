#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include "vpn.h"

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

enum class Reply { Valid, WrongId, Stalled, Truncated, Drip };

static bool exchange(Reply reply) {
  SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  require(listener != INVALID_SOCKET, "Cannot create fixture socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
    listen(listener, 1) == 0, "Cannot listen on loopback");
  int size = sizeof(address);
  require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0,
    "Cannot read fixture port");
  std::thread fixture([&] {
    SOCKET peer = accept(listener, nullptr, nullptr);
    if (peer == INVALID_SOCKET) return;
    DWORD timeout = 1000;
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    unsigned char request[64]{};
    int received = 0;
    while (received < 31) {
      int count = recv(peer, reinterpret_cast<char*>(request + received), 31 - received, 0);
      if (count <= 0) break;
      received += count;
    }
    if (reply == Reply::Stalled) Sleep(350);
    else {
      unsigned char response[14]{0, 12, request[2], request[3], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0};
      if (reply == Reply::WrongId) response[3] ^= 1;
      const int count = reply == Reply::Truncated ? 7 : 14;
      // Fragment the response so a successful read must assemble the header.
      for (int i = 0; i < count; ++i) {
        send(peer, reinterpret_cast<char*>(response + i), 1, 0);
        Sleep(reply == Reply::Drip ? 35 : 1);
      }
    }
    closesocket(peer);
  });
  const bool healthy = etlvpn::probeDnsTcp("127.0.0.1", ntohs(address.sin_port),
    reply == Reply::Valid ? 1000 : 200);
  fixture.join();
  closesocket(listener);
  return healthy;
}

static void watchPolicy() {
  using namespace std::chrono_literals;
  using Clock = etlvpn::TunnelWatch::Clock;
  const etlvpn::HealthReport healthy{true, true}, dnsBlocked{true, false}, down{false, false};
  const auto start = Clock::now();

  etlvpn::TunnelWatch watch(start);
  require(!watch.due(start + 2s), "Health check ran before the startup grace");
  require(watch.due(start + 3s), "Health check never became due");
  auto at = start + 3s;
  require(watch.record(down, at), "One missed check restored the network");
  require(watch.due(at + 2s) && !watch.due(at + 1s), "A failing tunnel was not rechecked quickly");
  require(watch.record(down, at += 2s), "Two missed checks restored the network");
  require(watch.record(healthy, at += 2s) && watch.failures() == 0, "A recovery did not clear the failures");
  require(!watch.due(at + 3s) && watch.due(at + 4s), "A healthy tunnel was rechecked too often");
  require(watch.record(down, at += 4s) && watch.record(down, at += 2s),
    "Failures before a recovery were not forgotten");
  require(!watch.record(down, at += 2s), "Consecutive tunnel failures never restored the network");

  // Other VPNs block UDP port 53 outside their own adapter. That must be
  // reported without ever disconnecting a tunnel that still relays traffic.
  etlvpn::TunnelWatch filtered(start);
  at = start + 3s;
  for (int i = 0; i < 100; ++i, at += 4s)
    require(filtered.record(dnsBlocked, at), "Blocked UDP DNS disconnected a working tunnel");
  require(!filtered.dnsViaTunnel(), "Blocked UDP DNS was not reported");
  require(filtered.record(healthy, at) && filtered.dnsViaTunnel(), "Restored DNS was not reported");
  require(etlvpn::TunnelWatch(start).dnsViaTunnel(), "DNS was reported blocked before the first check");
}

// The reported bug: Selective ended with "Tunnel lost" after a few failed
// server checks. It must pause and resume instead, and never ask to stop.
static void selectiveHealthPolicy() {
  using namespace std::chrono_literals;
  using Change = etlvpn::SelectiveHealth::Change;
  const auto start = etlvpn::SelectiveHealth::Clock::now();
  etlvpn::SelectiveHealth health(start);
  require(!health.due(start + 2s) && health.due(start + 3s), "Selective checked before the startup grace");
  auto at = start + 3s;
  require(health.record(false, at) == Change::None && health.record(false, at += 2s) == Change::None,
    "Isolated server failures paused Selective");
  require(health.record(true, at += 2s) == Change::None && !health.paused(), "A recovery left Selective paused");
  require(health.record(false, at += 4s) == Change::None && health.record(false, at += 2s) == Change::None,
    "Failures before a recovery were not forgotten");
  require(health.record(false, at += 2s) == Change::Pause && health.paused(),
    "Consecutive server failures did not pause Selective");
  for (int i = 0; i < 50; ++i)
    require(health.record(false, at += 2s) == Change::None && health.paused(),
      "A long outage stopped or re-paused Selective");
  require(health.due(at + 2s), "A paused Selective stopped retrying the server");
  require(health.record(true, at += 2s) == Change::Resume && !health.paused(),
    "Selective did not resume when the server answered");
  require(health.record(true, at += 4s) == Change::None, "A healthy server resumed Selective twice");
}

// Full mode no longer ends when the tunnel drops: it waits for the server on
// this schedule. Retries start quickly and settle at the limit, never faster.
static void retryPolicy() {
  using namespace std::chrono_literals;
  const auto start = etlvpn::RetrySchedule::Clock::now();
  etlvpn::RetrySchedule retry;
  retry.reset(start);
  require(!retry.due(start + 1s) && retry.due(start + 2s), "The first reconnection check was not quick");
  auto at = start + 2s;
  const int expected[]{4, 8, 16, 30, 30, 30};
  for (const int seconds : expected) {
    retry.failed(at);
    require(retry.delay().count() == seconds, "Reconnection checks did not back off as expected");
    require(!retry.due(at + std::chrono::seconds(seconds - 1)) && retry.due(at + std::chrono::seconds(seconds)),
      "A reconnection check ran at the wrong time");
    at += std::chrono::seconds(seconds);
  }
  retry.reset(at);
  require(retry.delay().count() == 2 && retry.due(at + 2s), "A new outage did not start with quick checks");
}

static void pathPolicy() {
  etlvpn::RoutePlan wifi{"13.140.191.31", "172.16.70.1", 12, true};
  etlvpn::RoutePlan roamed = wifi, cable = wifi, down;
  roamed.gateway = "192.168.0.1";
  cable.interfaceIndex = 7;
  require(!etlvpn::pathChanged(wifi, wifi), "An unchanged path was reported as moved");
  require(etlvpn::pathChanged(wifi, roamed), "A new gateway on the same adapter was missed");
  require(etlvpn::pathChanged(wifi, cable), "A switch to another adapter was missed");
  require(!etlvpn::pathChanged(wifi, down), "A missing default route must not move the tunnel");
}

static uint32_t ip(const char* text) {
  in_addr value{};
  require(inet_pton(AF_INET, text, &value) == 1, "Invalid fixture address");
  return value.s_addr;
}

static void selectivePolicy() {
  const uint32_t relay = ip("178.128.255.126"), server = ip("13.140.191.31");
  const auto stuck = MIB_TCP_STATE_SYN_SENT;
  require(etlvpn::selectiveCandidate(L"Twingate.Service.exe", stuck, relay, 30501, server),
    "A blocked Twingate relay attempt was not routed");
  require(etlvpn::selectiveCandidate(L"TWINGATE.SERVICE.EXE", stuck, relay, 30506, server),
    "Image names must match case-insensitively");
  require(!etlvpn::selectiveCandidate(L"Twingate.Service.exe", MIB_TCP_STATE_ESTAB, relay, 30501, server),
    "A working connection would be re-routed mid-stream");
  for (const uint16_t allowed : {53, 80, 443})
    require(!etlvpn::selectiveCandidate(L"Twingate.Service.exe", stuck, relay, allowed, server),
      "A port the network allows was routed");
  require(!etlvpn::selectiveCandidate(L"Twingate.Service.exe", stuck, server, 30501, server),
    "The ETL server itself would be routed into its own tunnel");
  for (const char* local : {"10.1.2.3", "172.16.79.254", "192.168.0.1", "100.96.30.29", "127.0.0.1",
                            "169.254.1.1", "198.18.0.2", "198.19.4.1", "224.0.0.251", "0.0.0.0"})
    require(!etlvpn::selectiveCandidate(L"Twingate.Service.exe", stuck, ip(local), 30501, server),
      "A private, local or special address was routed");
  require(!etlvpn::selectiveCandidate(L"chrome.exe", stuck, relay, 30501, server),
    "Another application's traffic was routed");
  require(!etlvpn::selectiveCandidate(L"Twingate.Service.exe.bak", stuck, relay, 30501, server),
    "A similar image name matched");
  require(etlvpn::ipv4Text(relay) == "178.128.255.126", "Addresses lost their byte order");
}

int main() {
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
  try {
    watchPolicy();
    selectivePolicy();
    selectiveHealthPolicy();
    retryPolicy();
    pathPolicy();
    require(exchange(Reply::Valid), "Healthy DNS relay rejected");
    require(!exchange(Reply::WrongId), "Unrelated DNS reply accepted");
    require(!exchange(Reply::Truncated), "Truncated relay reply accepted");
    const auto started = std::chrono::steady_clock::now();
    require(!exchange(Reply::Stalled), "Silent relay considered healthy");
    require(std::chrono::steady_clock::now() - started < std::chrono::seconds(3),
      "Silent relay exceeded its deadline");
    require(!exchange(Reply::Drip), "Partial replies extended the absolute probe deadline");
    require(!etlvpn::probeDnsTcp("invalid", 53, 200), "Invalid address accepted");
    std::cout << "VPN health checks passed\n";
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    WSACleanup();
    return 1;
  }
  WSACleanup();
  return 0;
}
