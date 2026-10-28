#pragma once
#include <windows.h>
#include <d3d11.h>
#include <array>
#include <cstdint>
#include <string>
#include "updater.h"

struct DesktopForm {
  std::array<char, 256> server{}, backup{};
  std::array<char, 65> token{}, backupToken{};
  std::array<char, 1024> ca{};
  int remotePort = 443, backupPort = 443, localPort = 1080, timeout = 5000;
  bool savedToken = false, savedBackupToken = false;
  bool fullMode = false;
};

struct DesktopState {
  bool running = false, stopping = false;
  bool starting = false, fullMode = false;
  int sessions = 0;
  uint64_t sent = 0, received = 0, failures = 0;
  std::string error;
  UpdateState update;
};

enum class DesktopAction { None, ToggleConnection, OpenBrowser, SaveSettings, CheckUpdates, InstallUpdate, DismissUpdate };
enum class DesktopMotion { System, Enabled, Reduced };

class DesktopUi {
 public:
  bool initialize(HWND window, DesktopMotion motion = DesktopMotion::System);
  DesktopAction render(DesktopForm& form, const DesktopState& state, float previewStep = 0);
  void resize(unsigned width, unsigned height);
  void shutdown();
  bool capture(const std::wstring& path);
  bool message(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  void showOptions(bool show = true) { if (options_ != show) { options_ = show; pageAlpha_ = 0; } }
 private:
  bool createTarget();
  void releaseDevice();
  void animateHeight(float target, float delta);
  HWND window_ = nullptr;
  ID3D11Device* device_ = nullptr;
  ID3D11DeviceContext* context_ = nullptr;
  IDXGISwapChain* swap_ = nullptr;
  ID3D11RenderTargetView* target_ = nullptr;
  bool initialized_ = false;
  float modePosition_ = 0, pageAlpha_ = 1;
  bool motion_ = true;
  DesktopMotion motionPreference_ = DesktopMotion::System;
  bool options_ = false;
  float height_ = 0, heightFrom_ = 0, heightTarget_ = 0, heightElapsed_ = 0;
  float contentHeight_ = 460;
};
