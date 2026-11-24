#pragma once
#include <windows.h>
#include <d3d11.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include "updater.h"

// Proxy only opens the local listener. Selective and Full run the elevated TUN
// worker: Selective routes only stuck relay connections (Twingate), Full routes
// the whole PC.
enum class DesktopMode { Proxy, Selective, Full };

struct DesktopForm {
  std::array<char, 256> server{}, backup{};
  std::array<char, 65> token{}, backupToken{};
  std::array<char, 1024> ca{};
  int remotePort = 443, backupPort = 443, localPort = 1080, timeout = 5000;
  bool savedToken = false, savedBackupToken = false;
  DesktopMode mode = DesktopMode::Proxy;
  std::string selectedAgent;
  std::array<char, 65> agentName{};
  int agentPort = 8443, agentPlatform = 0;
};

struct DesktopServer {
  std::string id, name, host;
  bool online = false;
};

struct DesktopState {
  bool running = false, stopping = false;
  bool starting = false;
  DesktopMode mode = DesktopMode::Proxy;  // of the active or starting connection
  // Full mode is up but system DNS cannot reach the tunnel (another VPN or
  // firewall blocks UDP 53); connections still use ETL.
  bool dnsBypassed = false;
  int routed = 0;  // Selective: destinations currently routed through ETL
  // The tunnel is waiting for the ETL server: Selective leaves Twingate on the
  // normal network, Full mode leaves the whole PC on it until it reconnects.
  bool paused = false;
  int sessions = 0;
  uint64_t sent = 0, received = 0, failures = 0;
  std::string error;
  UpdateState update;
  std::vector<DesktopServer> servers;
  bool agentsBusy = false;
  std::string agentMessage, activeServer;
  bool diagnosticsCopied = false;  // shown briefly after Copy diagnostics
};

enum class DesktopAction { None, ToggleConnection, OpenBrowser, SaveSettings, CheckUpdates, InstallUpdate,
  DismissUpdate, RefreshServers, ExportAgent, RemoveServer, SelectServer, CopyDiagnostics };
enum class DesktopMotion { System, Enabled, Reduced };

class DesktopUi {
 public:
  bool initialize(HWND window, DesktopMotion motion = DesktopMotion::System);
  DesktopAction render(DesktopForm& form, const DesktopState& state, float previewStep = 0);
  void resize(unsigned width, unsigned height);
  void shutdown();
  bool capture(const std::wstring& path);
  bool message(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  // Monitor scale (DPI / 96). Layout, fonts and the window follow it.
  void setScale(float scale);
  float scale() const { return scale_; }
  void showOptions(bool show = true) { if (options_ != show || servers_) { options_ = show; servers_ = false; pageAlpha_ = 0; } }
  void showServers() { options_ = false; servers_ = true; exporting_ = false; pageAlpha_ = 0; }
  void showAgentExport() { showServers(); exporting_ = true; }
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
  bool servers_ = false, exporting_ = false;
  float height_ = 0, heightFrom_ = 0, heightTarget_ = 0, heightElapsed_ = 0;
  float contentHeight_ = 460;
  float scale_ = 1;
};
