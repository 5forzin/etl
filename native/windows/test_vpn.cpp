#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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

int main() {
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
  try {
    watchPolicy();
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
