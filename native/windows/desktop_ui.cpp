#include "desktop_ui.h"
#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "etl_font.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <filesystem>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {
const ImVec4 background{.078f, .09f, .086f, 1}, surface{.118f, .133f, .125f, 1};
const ImVec4 accent{.722f, .925f, .816f, 1}, muted{.631f, .667f, .643f, 1};
ImFont *body = nullptr, *heading = nullptr, *brand = nullptr;

void centerText(const char* value) {
  ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(value).x) / 2);
  ImGui::TextUnformatted(value);
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

bool DesktopUi::initialize(HWND window) {
  window_ = window;
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
  heading = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 20, &font);
  brand = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 22, &font);
  if (!body || !heading || !brand) { ImGui::DestroyContext(); releaseDevice(); return false; }
  auto& style = ImGui::GetStyle();
  ImGui::StyleColorsDark();
  style.WindowPadding = {20, 16};
  style.FramePadding = {12, 8};
  style.ItemSpacing = {10, 6};
  style.FrameRounding = 10;
  style.WindowBorderSize = 0;
  style.FrameBorderSize = 1;
  style.Colors[ImGuiCol_WindowBg] = background;
  style.Colors[ImGuiCol_FrameBg] = surface;
  style.Colors[ImGuiCol_FrameBgHovered] = {.16f, .19f, .17f, 1};
  style.Colors[ImGuiCol_FrameBgActive] = {.18f, .22f, .19f, 1};
  style.Colors[ImGuiCol_Border] = {.204f, .231f, .216f, 1};
  style.Colors[ImGuiCol_Text] = {.933f, .945f, .937f, 1};
  style.Colors[ImGuiCol_Header] = surface;
  style.Colors[ImGuiCol_HeaderHovered] = {.16f, .19f, .17f, 1};
  style.Colors[ImGuiCol_Button] = surface;
  style.Colors[ImGuiCol_ButtonHovered] = {.19f, .23f, .20f, 1};
  style.Colors[ImGuiCol_ButtonActive] = {.23f, .28f, .25f, 1};
  style.Colors[ImGuiCol_CheckMark] = accent;
  if (!ImGui_ImplWin32_Init(window)) { ImGui::DestroyContext(); releaseDevice(); return false; }
  if (!ImGui_ImplDX11_Init(device_, context_)) {
    ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext(); releaseDevice(); return false;
  }
  initialized_ = true;
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
  target = std::ceil(std::max(360.f, target));
  if (target != heightTarget_) {
    heightFrom_ = height_;
    heightTarget_ = target;
    heightElapsed_ = 0;
  }
  constexpr float duration = .28f;
  heightElapsed_ = std::min(duration, heightElapsed_ + std::min(delta, .05f));
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

bool DesktopUi::render(DesktopForm& form, const DesktopState& state, float previewStep) {
  if (!initialized_ || !target_) {
    shutdown();
    if (!initialize(window_)) { Sleep(100); return false; }
  }
  animateHeight(contentHeight_, previewStep > 0 ? previewStep : ImGui::GetIO().DeltaTime);
  if (!target_) return false;
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  // Hidden previews advance motion deterministically without sleeping.
  if (previewStep > 0) ImGui::GetIO().DeltaTime = previewStep;
  ImGui::NewFrame();
  const float delta = ImGui::GetIO().DeltaTime;
  const float blend = 1 - std::exp(-delta / .18f);
  active_ += ((state.running && !state.stopping ? 1.f : 0.f) - active_) * blend;
  ImGui::SetNextWindowPos({0, 0});
  ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
  ImGui::Begin("etl", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
    ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  // Window controls stay outside the native drag region.
  auto chromeButton = [](const char* id, int symbol) {
    const auto p = ImGui::GetCursorScreenPos();
    bool clicked = ImGui::InvisibleButton(id, {28, 28});
    auto* d = ImGui::GetWindowDrawList();
    if (ImGui::IsItemHovered() || ImGui::IsItemFocused())
      d->AddRectFilled(p, {p.x + 28, p.y + 28}, ImGui::GetColorU32(surface), 7);
    const ImU32 color = ImGui::GetColorU32(muted);
    if (symbol == 0) d->AddLine({p.x + 9, p.y + 15}, {p.x + 19, p.y + 15}, color, 1.3f);
    else if (symbol == 1) {
      d->AddLine({p.x + 10, p.y + 10}, {p.x + 18, p.y + 18}, color, 1.3f);
      d->AddLine({p.x + 18, p.y + 10}, {p.x + 10, p.y + 18}, color, 1.3f);
    }
    return clicked;
  };
  const auto brandOrigin = ImGui::GetCursorScreenPos();
  drawBrand(ImGui::GetWindowDrawList(), {brandOrigin.x, brandOrigin.y + 2}, 24, ImGui::GetColorU32(ImGuiCol_Text));
  ImGui::Dummy({24, 28}); ImGui::SameLine(0, 7);
  ImGui::PushFont(brand); ImGui::TextUnformatted("etl"); ImGui::PopFont();
  ImGui::SameLine(); ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 82);
  if (chromeButton("##minimize", 0)) ShowWindow(window_, SW_MINIMIZE);
  ImGui::SameLine(0, 6);
  if (chromeButton("##close", 1)) PostMessageW(window_, WM_CLOSE, 0, 0);
  ImGui::Dummy({0, 4});
  bool toggle = false;
  const float width = ImGui::GetContentRegionAvail().x;
  ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 72) / 2);
  const ImVec2 start = ImGui::GetCursorScreenPos();
  ImGui::BeginDisabled(state.stopping);
  toggle = ImGui::InvisibleButton("##power", {72, 72});
  ImGui::EndDisabled();
  ImVec2 c{start.x + 36, start.y + 36};
  auto* draw = ImGui::GetWindowDrawList();
  hover_ += ((ImGui::IsItemHovered() ? 1.f : 0.f) - hover_) * blend;
  const ImU32 color = ImGui::GetColorU32(ImVec4{.63f + .09f * active_, .67f + .25f * active_, .64f + .17f * active_, 1});
  draw->AddCircleFilled(c, 35, ImGui::GetColorU32(ImVec4{surface.x + .052f*hover_, surface.y + .077f*hover_, surface.z + .055f*hover_, 1}), 64);
  draw->AddCircle(c, 35, ImGui::GetColorU32(ImVec4{.20f + .12f * active_, .24f + .23f * active_, .21f + .15f * active_, 1}), 64);
  draw->PathArcTo(c, 11, -.92f, 4.06f, 32);
  draw->PathStroke(color, 0, 2);
  draw->AddLine({c.x, c.y - 15}, {c.x, c.y - 2}, color, 2);
  if (ImGui::IsItemFocused()) draw->AddCircle(c, 38, color, 64, 2);
  if (ImGui::IsItemHovered()) ImGui::SetTooltip(state.running ? "Disconnect" : "Connect");
  ImGui::PushFont(heading);
  centerText(state.stopping ? "Stopping" : state.running ? "Proxy active" : "Off");
  ImGui::PopFont();
  ImGui::PushStyleColor(ImGuiCol_Text, muted);
  std::string endpoint = "127.0.0.1:" + std::to_string(form.localPort);
  centerText(endpoint.c_str());
  ImGui::PopStyleColor();
  ImGui::Dummy({0, 2});
  ImGui::BeginDisabled(state.running || state.stopping);
  input("Server", "etl.nora.systems", form.server.data(), form.server.size());
  input("Token", form.savedToken ? "Saved" : "", form.token.data(), form.token.size(), true);
  ImGui::EndDisabled();
  ImGui::Dummy({0, 4});
  ImGui::TextColored(muted, "%d %s", state.sessions, state.sessions == 1 ? "connection" : "connections");
  ImGui::SameLine(ImGui::GetStyle().WindowPadding.x + width * .44f);
  ImGui::TextColored(muted, "↑ %s", bytes(state.sent).c_str());
  ImGui::SameLine(ImGui::GetStyle().WindowPadding.x + width * .75f);
  ImGui::TextColored(muted, "↓ %s", bytes(state.received).c_str());
  ImGui::Dummy({0, 4});
  if (!state.error.empty()) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{1, .65f, .60f, 1});
    ImGui::TextWrapped("%s", state.error.c_str());
    ImGui::PopStyleColor();
  }
  if (state.failures) ImGui::TextColored(muted, "%llu %s", static_cast<unsigned long long>(state.failures),
    state.failures == 1 ? "failure" : "failures");
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4{0, 0, 0, 0});
  ImGui::PushStyleColor(ImGuiCol_Text, muted);
  ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0);
  if (ImGui::Button("Options", {-1, 28})) options_ = !options_;
  const auto optionsBounds = ImGui::GetItemRectMax();
  const float alphaBlend = 1 - std::exp(-delta / .08f);
  optionsAlpha_ += ((options_ ? 1.f : 0.f) - optionsAlpha_) * alphaBlend;
  // The chevron rotates as the disclosure opens and closes.
  const ImVec2 pivot{optionsBounds.x - 14, optionsBounds.y - 14};
  const float angle = optionsAlpha_ * 1.5707963f;
  auto rotate = [&](float x, float y) {
    return ImVec2{pivot.x + x * std::cos(angle) - y * std::sin(angle),
      pivot.y + x * std::sin(angle) + y * std::cos(angle)};
  };
  draw->AddLine(rotate(-2, -4), rotate(2, 0), ImGui::GetColorU32(muted), 1.3f);
  draw->AddLine(rotate(2, 0), rotate(-2, 4), ImGui::GetColorU32(muted), 1.3f);
  ImGui::PopStyleVar();
  ImGui::PopStyleColor(2);
  float contentBottom = optionsBounds.y;
  if (options_ || optionsAlpha_ > .01f) {
    ImGui::Dummy({0, 4});
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * optionsAlpha_);
    ImGui::BeginDisabled(state.running || state.stopping || !options_);
    ImGui::SetNextItemWidth(110); ImGui::InputInt("Remote port", &form.remotePort, 0);
    ImGui::SetNextItemWidth(110); ImGui::InputInt("Local port", &form.localPort, 0);
    ImGui::SetNextItemWidth(110); ImGui::InputInt("Timeout · ms", &form.timeout, 0);
    input("Backup", "", form.backup.data(), form.backup.size());
    ImGui::SetNextItemWidth(110); ImGui::InputInt("Backup port", &form.backupPort, 0);
    input("Backup token", form.savedBackupToken ? "Saved" : "Primary token", form.backupToken.data(), form.backupToken.size(), true);
    input("CA", "", form.ca.data(), form.ca.size());
    if (options_) contentBottom = ImGui::GetItemRectMax().y;
    ImGui::EndDisabled();
    ImGui::PopStyleVar();
  }
  contentHeight_ = contentBottom - ImGui::GetWindowPos().y + ImGui::GetStyle().WindowPadding.y;
  // Keep keyboard navigation from scrolling content during its reveal.
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
    initialize(window_);
  } else if (result == DXGI_STATUS_OCCLUDED && previewStep <= 0) Sleep(100);
  return toggle;
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
