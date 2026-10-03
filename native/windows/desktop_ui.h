#pragma once
#include <windows.h>
#include <d3d11.h>
#include <array>
#include <cstdint>
#include <string>

struct DesktopForm {
  std::array<char, 256> server{}, backup{};
  std::array<char, 65> token{}, backupToken{};
  std::array<char, 1024> ca{};
  int remotePort = 443, backupPort = 443, localPort = 1080, timeout = 1000;
  bool savedToken = false, savedBackupToken = false;
};

struct DesktopState {
  bool running = false, stopping = false;
  int sessions = 0;
  uint64_t sent = 0, received = 0, failures = 0;
  std::string error;
};

class DesktopUi {
 public:
  bool initialize(HWND window);
  bool render(DesktopForm& form, const DesktopState& state);
  void resize(unsigned width, unsigned height);
  void shutdown();
  bool capture(const std::wstring& path);
  bool message(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
 private:
  bool createTarget();
  void releaseDevice();
  HWND window_ = nullptr;
  ID3D11Device* device_ = nullptr;
  ID3D11DeviceContext* context_ = nullptr;
  IDXGISwapChain* swap_ = nullptr;
  ID3D11RenderTargetView* target_ = nullptr;
  bool initialized_ = false;
  float active_ = 0;
  float hover_ = 0;
};
