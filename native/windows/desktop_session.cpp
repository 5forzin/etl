#include "desktop_session.h"
#include <shellapi.h>
#include <sddl.h>
#include <objbase.h>
#include <new>
#include <algorithm>
#include <cstring>
#include <vector>

struct SessionMemory {
  DWORD version = 1, parent = 0, configurationSize = 0;
  volatile LONG phase = static_cast<LONG>(SessionPhase::Starting), sessions = 0;
  alignas(8) volatile LONG64 sent = 0, received = 0, failures = 0;
  char configuration[8192]{};
  char error[512]{};
};

namespace {
std::wstring objectName(const std::wstring& id, const wchar_t* suffix) {
  return L"Local\\ETL.Full." + id + suffix;
}

bool validId(const std::wstring& id) {
  return id.size() == 36 && std::all_of(id.begin(), id.end(), [](wchar_t c) {
    return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') ||
           (c >= L'a' && c <= L'f') || c == L'-';
  });
}

PSECURITY_DESCRIPTOR sessionSecurity() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> data(size);
  const bool ok = GetTokenInformation(token, TokenUser, data.data(), size, &size);
  CloseHandle(token);
  if (!ok) return nullptr;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) return nullptr;
  const std::wstring dacl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &descriptor, nullptr);
  return descriptor;
}
}

bool FullSession::start(const std::string& configuration, std::wstring& error, HWND owner, bool elevate) {
  if (exists()) { error = L"Full mode is already starting or active."; return false; }
  if (configuration.empty() || configuration.size() >= sizeof(SessionMemory::configuration)) {
    error = L"The connection settings are too large."; return false;
  }
  GUID guid{};
  wchar_t text[40]{}, executable[32768]{};
  const DWORD pathLength = GetModuleFileNameW(nullptr, executable, 32768);
  if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, text, 40) || !pathLength || pathLength >= 32768) {
    error = L"Full mode could not be prepared."; return false;
  }
  const std::wstring id(text + 1, 36);
  PSECURITY_DESCRIPTOR descriptor = sessionSecurity();
  if (!descriptor) { error = L"The private session could not be secured."; return false; }
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
  mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
    sizeof(SessionMemory), objectName(id, L".state").c_str());
  const bool newMapping = mapping_ && GetLastError() != ERROR_ALREADY_EXISTS;
  stop_ = CreateEventW(&security, TRUE, FALSE, objectName(id, L".stop").c_str());
  const bool newStop = stop_ && GetLastError() != ERROR_ALREADY_EXISTS;
  LocalFree(descriptor);
  if (newMapping && newStop)
    memory_ = static_cast<SessionMemory*>(MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SessionMemory)));
  if (!memory_) { error = L"The private session could not be created."; reset(); return false; }
  new (memory_) SessionMemory{};
  memory_->parent = GetCurrentProcessId();
  memory_->configurationSize = static_cast<DWORD>(configuration.size());
  std::memcpy(memory_->configuration, configuration.data(), configuration.size());
  MemoryBarrier();
  const std::wstring arguments = L"--desktop-full " + id + L" " + std::to_wstring(memory_->parent);
  DWORD launchError = ERROR_SUCCESS;
  if (elevate) {
    const HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SHELLEXECUTEINFOW launch{sizeof(launch)};
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    launch.hwnd = owner; launch.lpVerb = L"runas"; launch.lpFile = executable;
    launch.lpParameters = arguments.c_str(); launch.nShow = SW_HIDE;
    if (ShellExecuteExW(&launch)) process_ = launch.hProcess;
    else launchError = GetLastError();
    if (SUCCEEDED(apartment)) CoUninitialize();
  } else {
    // Offline transport tests use the same protocol without requesting UAC.
    std::wstring command = L"\"" + std::wstring(executable) + L"\" " + arguments;
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process)) {
      process_ = process.hProcess; CloseHandle(process.hThread);
    } else launchError = GetLastError();
  }
  if (!process_) {
    error = launchError == ERROR_CANCELLED ? L"Full mode was canceled. Your connection is unchanged." :
      L"Full mode could not start. Windows administrator permission is required.";
    reset(); return false;
  }
  return true;
}

bool FullSession::finished() const {
  return process_ && WaitForSingleObject(process_, 0) != WAIT_TIMEOUT;
}

SessionSnapshot FullSession::snapshot() const {
  SessionSnapshot out;
  if (!memory_) return out;
  out.phase = static_cast<SessionPhase>(InterlockedCompareExchange(&memory_->phase, 0, 0));
  out.sessions = InterlockedCompareExchange(&memory_->sessions, 0, 0);
  out.sent = InterlockedCompareExchange64(&memory_->sent, 0, 0);
  out.received = InterlockedCompareExchange64(&memory_->received, 0, 0);
  out.failures = InterlockedCompareExchange64(&memory_->failures, 0, 0);
  if (out.phase == SessionPhase::Failed)
    out.error.assign(memory_->error, strnlen(memory_->error, sizeof(memory_->error)));
  if (finished() && out.phase != SessionPhase::Stopped && out.phase != SessionPhase::Failed) {
    out.phase = SessionPhase::Failed;
    out.error = "Full mode exited unexpectedly. The recovery guard is restoring your connection.";
  }
  return out;
}

void FullSession::requestStop() { if (stop_) SetEvent(stop_); }

void FullSession::reset() {
  requestStop();
  if (memory_) { UnmapViewOfFile(memory_); memory_ = nullptr; }
  for (HANDLE* handle : {&process_, &stop_, &mapping_})
    if (*handle) { CloseHandle(*handle); *handle = nullptr; }
}

bool FullSessionWorker::open(const std::wstring& id, DWORD parent) {
  if (!validId(id) || !parent) return false;
  parent_ = OpenProcess(SYNCHRONIZE, FALSE, parent);
  mapping_ = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, objectName(id, L".state").c_str());
  stop_ = OpenEventW(SYNCHRONIZE, FALSE, objectName(id, L".stop").c_str());
  if (!parent_ || !mapping_ || !stop_) return false;
  memory_ = static_cast<SessionMemory*>(MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SessionMemory)));
  return memory_ && memory_->version == 1 && memory_->parent == parent &&
    memory_->configurationSize > 0 && memory_->configurationSize < sizeof(memory_->configuration) &&
    WaitForSingleObject(parent_, 0) == WAIT_TIMEOUT;
}

std::string FullSessionWorker::configuration() const {
  if (!memory_) return "";
  const DWORD size = memory_->configurationSize;
  return size > 0 && size < sizeof(memory_->configuration) ? std::string(memory_->configuration, size) : "";
}

bool FullSessionWorker::wait(DWORD milliseconds) const {
  HANDLE handles[]{stop_, parent_};
  return WaitForMultipleObjects(2, handles, FALSE, milliseconds) != WAIT_TIMEOUT;
}

void FullSessionWorker::publish(SessionPhase phase, const std::string& error) {
  if (!memory_) return;
  if (phase == SessionPhase::Failed) {
    std::memset(memory_->error, 0, sizeof(memory_->error));
    std::memcpy(memory_->error, error.data(), std::min(error.size(), sizeof(memory_->error) - 1));
  }
  InterlockedExchange(&memory_->phase, static_cast<LONG>(phase));
}

void FullSessionWorker::traffic(int sessions, uint64_t sent, uint64_t received, uint64_t failures) {
  if (!memory_) return;
  InterlockedExchange(&memory_->sessions, sessions);
  InterlockedExchange64(&memory_->sent, sent);
  InterlockedExchange64(&memory_->received, received);
  InterlockedExchange64(&memory_->failures, failures);
}

FullSessionWorker::~FullSessionWorker() {
  if (memory_) UnmapViewOfFile(memory_);
  for (HANDLE handle : {stop_, mapping_, parent_}) if (handle) CloseHandle(handle);
}
