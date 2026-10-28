#include "desktop_ui.h"
#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "etl_font.h"
#include "etl_version.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <filesystem>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {
const ImVec4 background{17 / 255.f, 17 / 255.f, 17 / 255.f, 1};
const ImVec4 surface{24 / 255.f, 24 / 255.f, 24 / 255.f, 1};
const ImVec4 raised{43 / 255.f, 43 / 255.f, 43 / 255.f, 1};
const ImVec4 accent{241 / 255.f, 241 / 255.f, 241 / 255.f, 1};
const ImVec4 muted{156 / 255.f, 156 / 255.f, 156 / 255.f, 1};
const ImVec4 border{54 / 255.f, 54 / 255.f, 54 / 255.f, 1};
ImFont *body = nullptr, *heading = nullptr, *brand = nullptr;
bool reduceMotion = false;

enum class Icon { Proxy, Full, Browser, Settings, Power, Stop, Back, Chevron, Minimize, Close, Upload, Download };

void icon(ImDrawList* draw, Icon kind, ImVec2 origin, float size, ImU32 color) {
  auto p = [&](float x, float y) { return ImVec2{origin.x + x * size / 24, origin.y + y * size / 24}; };
  const float stroke = 1.45f * size / 24;
  auto line = [&](float x, float y, float x2, float y2) { draw->AddLine(p(x, y), p(x2, y2), color, stroke); };
  switch (kind) {
    case Icon::Proxy:
      draw->AddRect(p(3, 6), p(10, 18), color, 3, 0, stroke);
      draw->AddRect(p(14, 6), p(21, 18), color, 3, 0, stroke);
      line(10, 12, 14, 12); break;
    case Icon::Full:
      draw->AddCircle(p(12, 12), size * 9 / 24, color, 32, stroke);
      draw->AddEllipse(p(12, 12), {size * 4 / 24, size * 9 / 24}, color, 0, 32, stroke);
      line(3, 12, 21, 12); break;
    case Icon::Browser:
      draw->AddRect(p(3, 4), p(21, 20), color, 4, 0, stroke);
      line(3, 9, 21, 9); draw->AddCircleFilled(p(7, 6.5f), .7f, color, 8); break;
    case Icon::Settings:
      for (int i = 0; i < 6; ++i) {
        const float a = (i * 60 - 30) * 3.14159265f / 180;
        draw->PathLineTo(p(12 + 9 * std::cos(a), 12 + 9 * std::sin(a)));
      }
      draw->PathStroke(color, ImDrawFlags_Closed, stroke);
      draw->AddCircle(p(12, 12), size * 2.7f / 24, color, 24, stroke); break;
    case Icon::Power:
      draw->PathArcTo(p(12, 12), size * 8 / 24, -1.0f, 4.14f, 32);
      draw->PathStroke(color, 0, stroke); line(12, 2, 12, 11); break;
    case Icon::Stop: draw->AddRect(p(6, 6), p(18, 18), color, 3, 0, stroke); break;
    case Icon::Back: line(14, 6, 8, 12); line(8, 12, 14, 18); break;
    case Icon::Chevron: line(9, 7, 14, 12); line(14, 12, 9, 17); break;
    case Icon::Minimize: line(7, 13, 17, 13); break;
    case Icon::Close: line(7, 7, 17, 17); line(17, 7, 7, 17); break;
    case Icon::Upload: line(12, 19, 12, 5); line(7, 10, 12, 5); line(12, 5, 17, 10); break;
    case Icon::Download: line(12, 5, 12, 19); line(7, 14, 12, 19); line(12, 19, 17, 14); break;
  }
}

float hoverFade(const char* id, bool target) {
  const auto key = ImGui::GetID(id);
  auto* storage = ImGui::GetStateStorage();
  float value = storage->GetFloat(key);
  value += ((target ? 1.f : 0.f) - value) * (reduceMotion ? 1.f : 1 - std::exp(-ImGui::GetIO().DeltaTime / .09f));
  storage->SetFloat(key, value);
  return value;
}

bool button(const char* label, ImVec2 size, Icon symbol, bool primary = false, bool row = false) {
  const auto p = ImGui::GetCursorScreenPos();
  const bool clicked = ImGui::InvisibleButton(label, size, ImGuiButtonFlags_EnableNav);
  const bool focused = ImGui::IsItemFocused() && ImGui::GetIO().NavVisible;
  const float hover = hoverFade(label, ImGui::IsItemHovered() || focused);
  const float press = ImGui::IsItemActive() ? .04f : 0;
  auto* draw = ImGui::GetWindowDrawList();
  ImVec4 fill = primary ? accent : surface;
  const float shade = primary ? -.10f * hover - press : .055f * hover + press;
  fill.x += shade; fill.y += shade; fill.z += shade;
  if (row) fill.w = hover;
  draw->AddRectFilled(p, {p.x + size.x, p.y + size.y}, ImGui::GetColorU32(fill), primary ? size.y / 2 : 14);
  if (focused) draw->AddRect({p.x - 2, p.y - 2}, {p.x + size.x + 2, p.y + size.y + 2},
    ImGui::GetColorU32(muted), primary ? size.y / 2 : 16, 0, 1);
  const ImU32 foreground = ImGui::GetColorU32(primary ? background : accent);
  const bool iconOnly = label[0] == '#' && label[1] == '#';
  const float textWidth = iconOnly ? 0 : ImGui::CalcTextSize(label).x;
  const float left = row ? 14 : (size.x - (iconOnly ? 20 : textWidth + 30)) / 2;
  icon(draw, symbol, {p.x + left, p.y + (size.y - 20) / 2}, 20, foreground);
  if (!iconOnly) draw->AddText({p.x + left + 30, p.y + (size.y - ImGui::GetFontSize()) / 2}, foreground, label);
  if (row) icon(draw, Icon::Chevron, {p.x + size.x - 32, p.y + (size.y - 18) / 2}, 18, ImGui::GetColorU32(muted));
  return clicked;
}

void drawBrand(ImDrawList* draw, ImVec2 origin, float size, ImU32 color) {
  const float scale = size / 64.f;
  auto point = [&](float x, float y) { return ImVec2{origin.x + x * scale, origin.y + y * scale}; };
  const float stroke = 8 * scale;
  draw->AddLine(point(40, 12), point(22, 12), color, stroke);
  draw->PathArcTo(point(22, 22), 10 * scale, 3.14159265f, 4.71238898f, 12);
  draw->PathStroke(color, 0, stroke);
  draw->AddLine(point(12, 22), point(12, 40), color, stroke);
  draw->AddLine(point(24, 52), point(42, 52), color, stroke);
  draw->PathArcTo(point(42, 42), 10 * scale, 0, 1.57079633f, 12);
  draw->PathStroke(color, 0, stroke);
  draw->AddLine(point(52, 42), point(52, 24), color, stroke);
  draw->AddLine(point(24, 32), point(40, 32), color, stroke);
  for (const ImVec2 endpoint : {point(40, 12), point(12, 40), point(24, 52), point(52, 24), point(24, 32), point(40, 32)})
    draw->AddCircleFilled(endpoint, stroke / 2, color, 12);
}

void input(const char* label, const char* hint, char* value, size_t size, bool secret = false) {
  ImGui::PushID(label);
  ImGui::TextColored(muted, "%s", label);
  ImGui::SetNextItemWidth(-1);
  ImGui::InputTextWithHint("##value", hint, value, size,
    secret ? ImGuiInputTextFlags_Password | ImGuiInputTextFlags_NoUndoRedo : 0);
  ImGui::PopID();
}

std::string bytes(uint64_t count) {
  char out[40];
  if (count < 1024) std::snprintf(out, sizeof(out), "%llu B", static_cast<unsigned long long>(count));
  else if (count < 1024 * 1024) std::snprintf(out, sizeof(out), "%.1f KB", count / 1024.0);
  else std::snprintf(out, sizeof(out), "%.1f MB", count / (1024.0 * 1024));
  return out;
}
}

bool DesktopUi::createTarget() {
  ID3D11Texture2D* back = nullptr;
  if (FAILED(swap_->GetBuffer(0, IID_PPV_ARGS(&back)))) return false;
  const HRESULT result = device_->CreateRenderTargetView(back, nullptr, &target_);
  back->Release();
  return SUCCEEDED(result);
}

void DesktopUi::releaseDevice() {
  if (target_) { target_->Release(); target_ = nullptr; }
  if (swap_) { swap_->Release(); swap_ = nullptr; }
  if (context_) { context_->Release(); context_ = nullptr; }
  if (device_) { device_->Release(); device_ = nullptr; }
}

bool DesktopUi::initialize(HWND window, DesktopMotion motion) {
  window_ = window;
  motionPreference_ = motion;
  DXGI_SWAP_CHAIN_DESC desc{};
  desc.BufferCount = 2;
  desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  desc.OutputWindow = window;
  desc.SampleDesc.Count = 1;
  desc.Windowed = TRUE;
  desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
  const D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
  auto create = [&](D3D_DRIVER_TYPE driver) {
    return D3D11CreateDeviceAndSwapChain(nullptr, driver, nullptr, 0, levels, 2,
      D3D11_SDK_VERSION, &desc, &swap_, &device_, nullptr, &context_);
  };
  if (FAILED(create(D3D_DRIVER_TYPE_HARDWARE))) {
    releaseDevice();
    if (FAILED(create(D3D_DRIVER_TYPE_WARP))) { releaseDevice(); return false; }
  }
  if (!createTarget()) { releaseDevice(); return false; }
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  auto& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.IniFilename = nullptr;
  io.LogFilename = nullptr;
  ImFontConfig font;
  font.FontDataOwnedByAtlas = false;
  body = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 14, &font);
  heading = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 26, &font);
  brand = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 18, &font);
  if (!body || !heading || !brand) { ImGui::DestroyContext(); releaseDevice(); return false; }
  auto& style = ImGui::GetStyle();
  ImGui::StyleColorsDark();
  style.WindowPadding = {24, 20};
  style.FramePadding = {12, 10};
  style.ItemSpacing = {12, 8};
  style.FrameRounding = 10;
  style.PopupRounding = 18;
  style.WindowRounding = 22;
  style.WindowBorderSize = 0;
  style.FrameBorderSize = 1;
  style.Colors[ImGuiCol_WindowBg] = background;
  style.Colors[ImGuiCol_FrameBg] = surface;
  style.Colors[ImGuiCol_FrameBgHovered] = {.13f, .13f, .13f, 1};
  style.Colors[ImGuiCol_FrameBgActive] = {.16f, .16f, .16f, 1};
  style.Colors[ImGuiCol_Border] = border;
  style.Colors[ImGuiCol_Text] = accent;
  style.Colors[ImGuiCol_TextDisabled] = muted;
  style.Colors[ImGuiCol_Separator] = border;
  style.Colors[ImGuiCol_Header] = surface;
  style.Colors[ImGuiCol_HeaderHovered] = raised;
  style.Colors[ImGuiCol_Button] = raised;
  style.Colors[ImGuiCol_ButtonHovered] = {.22f, .22f, .22f, 1};
  style.Colors[ImGuiCol_ButtonActive] = {.25f, .25f, .25f, 1};
  style.Colors[ImGuiCol_NavCursor] = accent;
  style.Colors[ImGuiCol_TextSelectedBg] = {.40f, .40f, .40f, .6f};
  style.Colors[ImGuiCol_CheckMark] = accent;
  if (!ImGui_ImplWin32_Init(window)) { ImGui::DestroyContext(); releaseDevice(); return false; }
  if (!ImGui_ImplDX11_Init(device_, context_)) {
    ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext(); releaseDevice(); return false;
  }
  initialized_ = true;
  BOOL animations = TRUE;
  if (motion == DesktopMotion::System) SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animations, 0);
  motion_ = motion == DesktopMotion::Enabled || (motion == DesktopMotion::System && animations != FALSE);
  reduceMotion = !motion_;
  return true;
}

bool DesktopUi::message(HWND window, UINT msg, WPARAM wp, LPARAM lp) {
  return initialized_ && ImGui_ImplWin32_WndProcHandler(window, msg, wp, lp);
}

void DesktopUi::resize(unsigned width, unsigned height) {
  if (!swap_ || !width || !height) return;
  context_->OMSetRenderTargets(0, nullptr, nullptr);
  if (target_) { target_->Release(); target_ = nullptr; }
  if (SUCCEEDED(swap_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0))) createTarget();
}

void DesktopUi::animateHeight(float target, float delta) {
  if (IsIconic(window_)) return;
  RECT bounds{}; GetWindowRect(window_, &bounds);
  if (!height_) height_ = heightFrom_ = heightTarget_ = static_cast<float>(bounds.bottom - bounds.top);
  target = std::ceil(std::max(440.f, target));
  if (target != heightTarget_) {
    heightFrom_ = height_;
    heightTarget_ = target;
    heightElapsed_ = 0;
  }
  constexpr float duration = .28f;
  heightElapsed_ = motion_ ? std::min(duration, heightElapsed_ + std::min(delta, .05f)) : duration;
  const float remaining = 1 - heightElapsed_ / duration;
  height_ = heightFrom_ + (heightTarget_ - heightFrom_) * (1 - remaining * remaining * remaining);
  const int height = static_cast<int>(std::lround(height_));
  if (height == bounds.bottom - bounds.top) return;
  int top = bounds.top;
  MONITORINFO monitor{sizeof(monitor)};
  if (GetMonitorInfoW(MonitorFromWindow(window_, MONITOR_DEFAULTTONEAREST), &monitor))
    top = std::max(monitor.rcWork.top, std::min(bounds.top, monitor.rcWork.bottom - height));
  // Called before NewFrame so the viewport and render target use the same size.
  SetWindowPos(window_, nullptr, bounds.left, top, bounds.right - bounds.left, height,
    SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOOWNERZORDER);
}

DesktopAction DesktopUi::render(DesktopForm& form, const DesktopState& state, float previewStep) {
  if (!initialized_ || !target_) {
    shutdown();
    if (!initialize(window_, motionPreference_)) { Sleep(100); return DesktopAction::None; }
  }
  animateHeight(contentHeight_, previewStep > 0 ? previewStep : ImGui::GetIO().DeltaTime);
  if (!target_) return DesktopAction::None;
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  // Hidden previews advance motion deterministically without sleeping.
  if (previewStep > 0) ImGui::GetIO().DeltaTime = previewStep;
  ImGui::NewFrame();
  const float delta = ImGui::GetIO().DeltaTime;
  const float blend = reduceMotion ? 1.f : 1 - std::exp(-delta / .10f);
  modePosition_ += ((form.fullMode ? 1.f : 0.f) - modePosition_) * blend;
  pageAlpha_ += (1 - pageAlpha_) * blend;
  ImGui::SetNextWindowPos({0, 0});
  ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
  ImGui::Begin("etl", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
    ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  auto* draw = ImGui::GetWindowDrawList();
  const auto windowSize = ImGui::GetWindowSize();
  draw->AddRect({.5f, .5f}, {windowSize.x - .5f, windowSize.y - .5f},
    ImGui::GetColorU32(border), 22, 0, 1);
  draw->AddRect({2, 2}, {windowSize.x - 2, windowSize.y - 2}, IM_COL32(31, 31, 31, 255), 21);
  const float width = ImGui::GetContentRegionAvail().x;
  const auto header = ImGui::GetCursorPos();
  if (options_) {
    if (button("##back", {28, 28}, Icon::Back)) showOptions(false);
    ImGui::SameLine(0, 8);
    ImGui::PushFont(brand); ImGui::TextUnformatted("Settings"); ImGui::PopFont();
  } else {
    const auto origin = ImGui::GetCursorScreenPos();
    drawBrand(draw, {origin.x, origin.y + 2}, 24, ImGui::GetColorU32(accent));
    ImGui::Dummy({24, 28}); ImGui::SameLine(0, 9);
    ImGui::PushFont(brand); ImGui::TextUnformatted("etl"); ImGui::PopFont();
  }
  ImGui::SetCursorPos({windowSize.x - 92, header.y - 2});
  if (button("##minimize", {28, 28}, Icon::Minimize)) ShowWindow(window_, SW_MINIMIZE);
  ImGui::SameLine(0, 6);
  if (button("##close", {28, 28}, Icon::Close)) PostMessageW(window_, WM_CLOSE, 0, 0);
  ImGui::SetCursorPos({24, header.y + 52});
  ImGui::PushStyleVar(ImGuiStyleVar_Alpha, pageAlpha_);
  DesktopAction action = DesktopAction::None;
  const bool busy = state.running || state.starting || state.stopping;
  const auto& update = state.update;
  const bool downloading = update.phase == UpdatePhase::Downloading || update.phase == UpdatePhase::Ready;

  if (!options_) {
    const char* status = state.stopping ? "Disconnecting" : state.starting ? "Connecting" :
      state.running ? (state.fullMode ? "Connected" : "Proxy active") : "Disconnected";
    ImGui::PushFont(heading); ImGui::TextUnformatted(status); ImGui::PopFont();
    const auto statusPosition = ImGui::GetCursorScreenPos();
    if (state.running) {
      draw->AddCircleFilled({statusPosition.x + 3, statusPosition.y + 7}, 3,
        ImGui::GetColorU32(ImVec4{.65f, .78f, .65f, 1}), 16);
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 14);
    }
    ImGui::TextColored(muted, "%s", form.server[0] ? form.server.data() : "Server not set");
    ImGui::Dummy({0, 12});

    const auto selector = ImGui::GetCursorScreenPos();
    const float segment = (width - 8) / 2;
    draw->AddRectFilled(selector, {selector.x + width, selector.y + 48}, ImGui::GetColorU32(surface), 16);
    draw->AddRect(selector, {selector.x + width, selector.y + 48}, ImGui::GetColorU32(border), 16);
    const float selectedX = selector.x + 4 + segment * modePosition_;
    draw->AddRectFilled({selectedX, selector.y + 4}, {selectedX + segment, selector.y + 44},
      ImGui::GetColorU32(raised), 12);
    draw->AddRect({selectedX + .5f, selector.y + 4.5f}, {selectedX + segment - .5f, selector.y + 43.5f},
      ImGui::GetColorU32(ImVec4{.23f, .23f, .23f, 1}), 12);
    ImGui::BeginDisabled(busy);
    for (int mode = 0; mode < 2; ++mode) {
      ImGui::SetCursorScreenPos({selector.x + 4 + segment * mode, selector.y + 4});
      const char* label = mode ? "Full mode" : "Proxy only";
      if (ImGui::InvisibleButton(label, {segment, 40}, ImGuiButtonFlags_EnableNav)) form.fullMode = mode != 0;
      const bool selected = form.fullMode == (mode != 0);
      const float hover = hoverFade(label, ImGui::IsItemHovered());
      const ImU32 color = ImGui::GetColorU32(selected ? accent : ImVec4{muted.x + hover * .18f,
        muted.y + hover * .18f, muted.z + hover * .18f, 1});
      const float labelWidth = ImGui::CalcTextSize(label).x;
      const float x = selector.x + 4 + segment * mode + (segment - labelWidth - 28) / 2;
      icon(draw, mode ? Icon::Full : Icon::Proxy, {x, selector.y + 14}, 20, color);
      draw->AddText({x + 28, selector.y + 17}, color, label);
      if (ImGui::IsItemFocused() && ImGui::GetIO().NavVisible) draw->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(),
        ImGui::GetColorU32(muted), 12);
    }
    ImGui::EndDisabled();
    ImGui::SetCursorScreenPos({selector.x, selector.y + 64});
    ImGui::BeginDisabled(state.stopping);
    const char* connectLabel = state.stopping ? "Disconnecting…" : state.starting ? "Cancel" :
      state.running ? "Disconnect" : "Connect";
    if (button(connectLabel, {width, 46}, state.running || state.starting ? Icon::Stop : Icon::Power, true))
      action = DesktopAction::ToggleConnection;
    if (form.fullMode && !busy && ImGui::IsItemHovered()) ImGui::SetTooltip("Requires administrator permission.");
    ImGui::EndDisabled();
    ImGui::Dummy({0, 12});

    const auto panel = ImGui::GetCursorScreenPos();
    draw->AddRectFilled(panel, {panel.x + width, panel.y + 112}, ImGui::GetColorU32(surface), 20);
    draw->AddRect(panel, {panel.x + width, panel.y + 112}, ImGui::GetColorU32(border), 20);
    draw->AddRect({panel.x + 2, panel.y + 2}, {panel.x + width - 2, panel.y + 110},
      ImGui::GetColorU32(ImVec4{.115f, .115f, .115f, 1}), 19);
    ImGui::SetCursorScreenPos({panel.x + 8, panel.y + 6});
    ImGui::BeginDisabled(state.stopping || state.starting);
    if (button("Open browser", {width - 16, 48}, Icon::Browser, false, true)) action = DesktopAction::OpenBrowser;
    ImGui::EndDisabled();
    draw->AddLine({panel.x + 20, panel.y + 56}, {panel.x + width - 20, panel.y + 56}, ImGui::GetColorU32(border));
    ImGui::SetCursorScreenPos({panel.x + 8, panel.y + 59});
    if (button("Settings", {width - 16, 47}, Icon::Settings, false, true)) showOptions();
    ImGui::SetCursorScreenPos({panel.x, panel.y + 128});
    ImGui::TextColored(muted, "127.0.0.1:%d", form.localPort);
    if (state.running) {
      ImGui::TextColored(muted, "%d %s", state.sessions, state.sessions == 1 ? "connection" : "connections");
      const auto sent = bytes(state.sent), received = bytes(state.received);
      const float sentWidth = ImGui::CalcTextSize(sent.c_str()).x;
      const float receivedWidth = ImGui::CalcTextSize(received.c_str()).x;
      ImGui::SameLine(); ImGui::SetCursorPosX(windowSize.x - 24 - sentWidth - receivedWidth - 52);
      auto position = ImGui::GetCursorScreenPos();
      icon(draw, Icon::Upload, {position.x, position.y - 1}, 16, ImGui::GetColorU32(muted));
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20); ImGui::TextColored(muted, "%s", sent.c_str());
      ImGui::SameLine(0, 12);
      position = ImGui::GetCursorScreenPos();
      icon(draw, Icon::Download, {position.x, position.y - 1}, 16, ImGui::GetColorU32(muted));
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20); ImGui::TextColored(muted, "%s", received.c_str());
    }
  } else {
    ImGui::BeginDisabled(busy);
    auto serverInputs = [&](const char* hostLabel, auto& host, int& port, const char* hint) {
      if (ImGui::BeginTable(hostLabel, 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 2.8f);
        ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthStretch, 1);
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextColored(muted, "%s", hostLabel);
        ImGui::TableNextColumn(); ImGui::TextColored(muted, "Port");
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##host", hint, host.data(), host.size());
        ImGui::TableNextColumn(); ImGui::SetNextItemWidth(-1); ImGui::InputInt("##port", &port, 0);
        ImGui::EndTable();
      }
    };
    serverInputs("Server", form.server, form.remotePort, "etl.nora.systems");
    input("Token", form.savedToken ? "Saved" : "", form.token.data(), form.token.size(), true);
    ImGui::Dummy({0, 6});
    ImGui::Separator();
    ImGui::Dummy({0, 4});
    serverInputs(form.fullMode ? "Backup (proxy only)" : "Backup server", form.backup, form.backupPort, "");
    input("Backup token", form.savedBackupToken ? "Saved" : "Primary token", form.backupToken.data(), form.backupToken.size(), true);
    ImGui::Dummy({0, 6});
    ImGui::Separator();
    ImGui::Dummy({0, 4});
    if (ImGui::BeginTable("Local connection", 2, ImGuiTableFlags_SizingStretchSame)) {
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextColored(muted, "Local port");
      ImGui::TableNextColumn(); ImGui::TextColored(muted, "Timeout (ms)");
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::SetNextItemWidth(-1); ImGui::InputInt("##local", &form.localPort, 0);
      ImGui::TableNextColumn(); ImGui::SetNextItemWidth(-1); ImGui::InputInt("##timeout", &form.timeout, 0);
      ImGui::EndTable();
    }
    input("CA certificate", "System trust store", form.ca.data(), form.ca.size());
    ImGui::Dummy({0, 10});
    if (button("Save", {width, 42}, Icon::Settings, true)) action = DesktopAction::SaveSettings;
    ImGui::EndDisabled();
    if (busy) ImGui::TextColored(muted, "Disconnect to edit.");
    ImGui::Dummy({0, 8});
    ImGui::Separator();
    ImGui::TextColored(muted, "v%s", etlVersion);
    ImGui::BeginDisabled(update.phase == UpdatePhase::Checking || downloading || state.stopping);
    if (button(update.phase == UpdatePhase::Checking ? "Checking…" : "Check for updates", {width, 36}, Icon::Download))
      action = DesktopAction::CheckUpdates;
    ImGui::EndDisabled();
    if (update.phase == UpdatePhase::Current) ImGui::TextColored(muted, "Up to date");
    if (!update.offered && !update.error.empty()) ImGui::TextWrapped("%s", update.error.c_str());
  }

  if (!state.error.empty()) {
    ImGui::Dummy({0, 6});
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{.94f, .66f, .63f, 1});
    ImGui::TextWrapped("%s", state.error.c_str());
    ImGui::PopStyleColor();
  }
  if (!options_ && update.offered) {
    ImGui::Dummy({0, 8}); ImGui::Separator(); ImGui::Dummy({0, 4});
    ImGui::TextUnformatted(downloading ? "Updating" : "Update available");
    ImGui::TextColored(muted, "%s → %s", etlVersion, update.version.c_str());
    if (downloading) {
      ImGui::PushStyleColor(ImGuiCol_PlotHistogram, accent);
      ImGui::ProgressBar(update.progress, {-1, 6}, "");
      ImGui::PopStyleColor();
      if (update.phase == UpdatePhase::Ready) ImGui::TextColored(muted, "Restarting…");
      else ImGui::TextColored(muted, "%d%%", static_cast<int>(update.progress * 100));
    } else {
      ImGui::PushStyleColor(ImGuiCol_Text, muted);
      ImGui::TextWrapped("%s", busy ? "Disconnects and restarts ETL." : "Restarts ETL.");
      ImGui::PopStyleColor();
      if (!update.error.empty()) ImGui::TextWrapped("%s", update.error.c_str());
      ImGui::BeginDisabled(state.starting || state.stopping);
      const float half = (width - 12) / 2;
      if (button("Later", {half, 38}, Icon::Close)) action = DesktopAction::DismissUpdate;
      ImGui::SameLine();
      if (button(update.phase == UpdatePhase::Failed ? "Retry" : "Update", {half, 38}, Icon::Download, true))
        action = DesktopAction::InstallUpdate;
      ImGui::EndDisabled();
    }
  }
  contentHeight_ = ImGui::GetCursorPosY() + 16;
  ImGui::PopStyleVar();
  ImGui::SetScrollY(0);
  ImGui::End();
  ImGui::Render();
  context_->OMSetRenderTargets(1, &target_, nullptr);
  const float clear[]{background.x, background.y, background.z, 1};
  context_->ClearRenderTargetView(target_, clear);
  ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
  const HRESULT result = swap_->Present(1, 0);
  if (result == DXGI_ERROR_DEVICE_REMOVED || result == DXGI_ERROR_DEVICE_RESET) {
    shutdown();
    initialize(window_, motionPreference_);
  } else if (result == DXGI_STATUS_OCCLUDED && previewStep <= 0) Sleep(100);
  return action;
}

void DesktopUi::shutdown() {
  if (initialized_) {
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    initialized_ = false;
  }
  releaseDevice();
}

bool DesktopUi::capture(const std::wstring& path) {
  ID3D11Texture2D *back = nullptr, *staging = nullptr;
  if (!swap_ || FAILED(swap_->GetBuffer(0, IID_PPV_ARGS(&back)))) return false;
  D3D11_TEXTURE2D_DESC desc{}; back->GetDesc(&desc);
  desc.Usage = D3D11_USAGE_STAGING; desc.BindFlags = 0; desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ; desc.MiscFlags = 0;
  if (FAILED(device_->CreateTexture2D(&desc, nullptr, &staging))) { back->Release(); return false; }
  context_->CopyResource(staging, back); back->Release();
  D3D11_MAPPED_SUBRESOURCE mapped{};
  if (FAILED(context_->Map(staging, 0, D3D11_MAP_READ, 0, &mapped))) { staging->Release(); return false; }
  std::ofstream file(std::filesystem::path(path), std::ios::binary);
  BITMAPFILEHEADER header{}; header.bfType = 0x4d42; header.bfOffBits = sizeof(header) + sizeof(BITMAPINFOHEADER);
  header.bfSize = header.bfOffBits + desc.Width * desc.Height * 4;
  BITMAPINFOHEADER info{}; info.biSize = sizeof(info); info.biWidth = desc.Width; info.biHeight = -static_cast<LONG>(desc.Height);
  info.biPlanes = 1; info.biBitCount = 32; info.biCompression = BI_RGB;
  file.write(reinterpret_cast<const char*>(&header), sizeof(header));
  file.write(reinterpret_cast<const char*>(&info), sizeof(info));
  for (UINT y = 0; y < desc.Height; ++y) {
    auto* row = static_cast<unsigned char*>(mapped.pData) + y * mapped.RowPitch;
    for (UINT x = 0; x < desc.Width; ++x) {
      const char bgra[]{static_cast<char>(row[x*4+2]), static_cast<char>(row[x*4+1]), static_cast<char>(row[x*4]), static_cast<char>(255)};
      file.write(bgra, 4);
    }
  }
  const bool ok = file.good();
  context_->Unmap(staging, 0); staging->Release(); return ok;
}
