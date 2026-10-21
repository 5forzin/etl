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

int main() {
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
  try {
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
