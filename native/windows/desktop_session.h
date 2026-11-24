#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

enum class SessionPhase : LONG { Starting, Running, Stopping, Stopped, Failed };

struct SessionSnapshot {
  SessionPhase phase = SessionPhase::Stopped;
  int sessions = 0;
  uint64_t sent = 0, received = 0, failures = 0;
  bool dnsBypassed = false;
  int routed = 0;
  bool paused = false;
  std::string error;
};

struct SessionMemory;

// Only the VPN worker is elevated. The desktop and browser retain normal rights.
class FullSession {
 public:
  FullSession() = default;
  FullSession(const FullSession&) = delete;
  FullSession& operator=(const FullSession&) = delete;
  bool start(const std::string& protectedConfiguration, std::wstring& error,
             HWND owner = nullptr, bool elevate = true);
  bool exists() const { return process_ != nullptr; }
  bool finished() const;
  SessionSnapshot snapshot() const;
  void requestStop();
  void reset();
  ~FullSession() { reset(); }
 private:
  HANDLE process_ = nullptr, mapping_ = nullptr, stop_ = nullptr;
  SessionMemory* memory_ = nullptr;
};

class FullSessionWorker {
 public:
  FullSessionWorker() = default;
  FullSessionWorker(const FullSessionWorker&) = delete;
  FullSessionWorker& operator=(const FullSessionWorker&) = delete;
  bool open(const std::wstring& id, DWORD parent);
  std::string configuration() const;
  bool wait(DWORD milliseconds) const;
  void publish(SessionPhase phase, const std::string& error = "");
  void traffic(int sessions, uint64_t sent, uint64_t received, uint64_t failures);
  // True when the tunnel works but system DNS cannot reach its mapped DNS.
  void dnsBypassed(bool bypassed);
  void routed(int destinations);  // Selective: destinations routed through the tunnel
  // Routes withdrawn until the server answers: Selective's relay routes, or
  // Full mode's whole tunnel (the PC is on its normal connection meanwhile).
  void paused(bool serverUnreachable);
  ~FullSessionWorker();
 private:
  HANDLE parent_ = nullptr, mapping_ = nullptr, stop_ = nullptr;
  SessionMemory* memory_ = nullptr;
};
