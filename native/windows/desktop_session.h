#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

enum class SessionPhase : LONG { Starting, Running, Stopping, Stopped, Failed };

struct SessionSnapshot {
  SessionPhase phase = SessionPhase::Stopped;
  int sessions = 0;
  uint64_t sent = 0, received = 0, failures = 0;
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
  ~FullSessionWorker();
 private:
  HANDLE parent_ = nullptr, mapping_ = nullptr, stop_ = nullptr;
  SessionMemory* memory_ = nullptr;
};
