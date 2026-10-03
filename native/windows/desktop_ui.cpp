#include "desktop_ui.h"
#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "etl_font.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {
const ImVec4 background{.078f, .09f, .086f, 1}, surface{.118f, .133f, .125f, 1};
const ImVec4 accent{.722f, .925f, .816f, 1}, muted{.631f, .667f, .643f, 1};
ImFont *body = nullptr, *heading = nullptr, *brand = nullptr;

void centerText(const char* value) {
  ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(value).x) / 2);
  ImGui::TextUnformatted(value);
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
  body = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 16, &font);
  heading = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 24, &font);
  brand = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(etlFont), sizeof(etlFont), 28, &font);
  if (!body || !heading || !brand) { ImGui::DestroyContext(); releaseDevice(); return false; }
  auto& style = ImGui::GetStyle();
  ImGui::StyleColorsDark();
  style.WindowPadding = {32, 28};
  style.FramePadding = {16, 13};
  style.ItemSpacing = {14, 12};
  style.FrameRounding = 12;
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

bool DesktopUi::render(DesktopForm& form, const DesktopState& state) {
  if (!initialized_ || !target_) return false;
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  ImGui::NewFrame();
  const float blend = 1 - std::exp(-ImGui::GetIO().DeltaTime / .18f);
  active_ += ((state.running && !state.stopping ? 1.f : 0.f) - active_) * blend;
  ImGui::SetNextWindowPos({0, 0});
  ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
  ImGui::Begin("etl", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
    ImGuiWindowFlags_NoSavedSettings);
  ImGui::PushFont(brand);
  ImGui::TextUnformatted("etl");
  ImGui::PopFont();
  ImGui::Spacing();
  const float width = ImGui::GetContentRegionAvail().x;
  ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 112) / 2);
  const ImVec2 start = ImGui::GetCursorScreenPos();
  ImGui::BeginDisabled(state.stopping);
  bool toggle = ImGui::InvisibleButton("##power", {112, 112});
  ImGui::EndDisabled();
  ImVec2 c{start.x + 56, start.y + 56};
  auto* draw = ImGui::GetWindowDrawList();
  const ImU32 color = ImGui::GetColorU32(ImVec4{.63f + .09f * active_, .67f + .25f * active_, .64f + .17f * active_, 1});
  draw->AddCircleFilled(c, 55, ImGui::GetColorU32(ImGui::IsItemHovered() ? ImVec4{.17f,.21f,.18f,1} : surface), 64);
  draw->AddCircle(c, 55, ImGui::GetColorU32(ImVec4{.20f, .24f, .21f, 1}), 64);
  draw->PathArcTo(c, 17, -3.9f, .76f, 40);
  draw->PathStroke(color, 0, 2.5f);
  draw->AddLine({c.x, c.y - 23}, {c.x, c.y - 3}, color, 2.5f);
  if (ImGui::IsItemFocused()) draw->AddCircle(c, 59, color, 64, 2);
  ImGui::PushFont(heading);
  centerText(state.stopping ? "Stopping" : state.running ? "Proxy active" : "Off");
  ImGui::PopFont();
  ImGui::PushStyleColor(ImGuiCol_Text, muted);
  std::string endpoint = "127.0.0.1:" + std::to_string(form.localPort);
  centerText(endpoint.c_str());
  ImGui::PopStyleColor();
  ImGui::Dummy({0, 16});
  ImGui::BeginDisabled(state.running || state.stopping);
  input("Server", "etl.nora.systems", form.server.data(), form.server.size());
  input("Token", form.savedToken ? "Saved" : "", form.token.data(), form.token.size(), true);
  ImGui::EndDisabled();
  ImGui::Dummy({0, 4});
  ImGui::TextColored(muted, "%d connections", state.sessions);
  ImGui::SameLine(width * .40f);
  ImGui::TextColored(muted, "↑ %s", bytes(state.sent).c_str());
  ImGui::SameLine(width * .73f);
  ImGui::TextColored(muted, "↓ %s", bytes(state.received).c_str());
  ImGui::Dummy({0, 4});
  ImGui::BeginDisabled(state.stopping);
  ImGui::PushStyleColor(ImGuiCol_Button, accent);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4{.80f, .96f, .87f, 1});
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4{.62f, .83f, .72f, 1});
  ImGui::PushStyleColor(ImGuiCol_Text, background);
  toggle |= ImGui::Button(state.stopping ? "Stopping" : state.running ? "Disconnect" : "Connect", {-1, 46});
  ImGui::PopStyleColor(4);
  ImGui::EndDisabled();
  if (!state.error.empty()) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{1, .65f, .60f, 1});
    ImGui::TextWrapped("%s", state.error.c_str());
    ImGui::PopStyleColor();
  }
  if (state.failures) ImGui::TextColored(muted, "%llu failures", static_cast<unsigned long long>(state.failures));
  if (ImGui::CollapsingHeader("Options")) {
    ImGui::BeginDisabled(state.running || state.stopping);
    ImGui::SetNextItemWidth(140); ImGui::InputInt("Remote port", &form.remotePort, 0);
    ImGui::SetNextItemWidth(140); ImGui::InputInt("Local port", &form.localPort, 0);
    ImGui::SetNextItemWidth(140); ImGui::InputInt("Timeout · ms", &form.timeout, 0);
    input("Backup", "", form.backup.data(), form.backup.size());
    ImGui::SetNextItemWidth(140); ImGui::InputInt("Backup port", &form.backupPort, 0);
    input("Backup token", form.savedBackupToken ? "Saved" : "Primary token", form.backupToken.data(), form.backupToken.size(), true);
    input("CA", "", form.ca.data(), form.ca.size());
    ImGui::EndDisabled();
  }
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
  } else if (result == DXGI_STATUS_OCCLUDED) Sleep(100);
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
