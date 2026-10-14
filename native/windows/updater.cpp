#include "updater.h"
#include "etl_version.h"
#include <winhttp.h>
#include <objbase.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <functional>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
constexpr uint64_t maxDownload = 128 * 1024 * 1024;
constexpr uint64_t checkInterval = 60 * 60 * 1000;

struct InternetHandle {
  HINTERNET value;
  ~InternetHandle() { if (value) WinHttpCloseHandle(value); }
  operator HINTERNET() const { return value; }
};

std::array<uint32_t, 3> versionParts(std::string value) {
  if (!value.empty() && value.front() == 'v') value.erase(0, 1);
  std::array<uint32_t, 3> result{};
  for (size_t i = 0; i < result.size(); ++i) {
    const auto dot = value.find('.');
    const auto part = value.substr(0, dot);
    if (part.empty() || (part.size() > 1 && part.front() == '0')) throw std::runtime_error("Unsupported release version.");
    const auto parsed = std::from_chars(part.data(), part.data() + part.size(), result[i]);
    if (parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size() ||
        (i < 2 ? dot == std::string::npos : dot != std::string::npos))
      throw std::runtime_error("Unsupported release version.");
    if (dot != std::string::npos) value.erase(0, dot + 1);
  }
  return result;
}

bool validHash(const std::string& value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
  });
}

std::filesystem::path executablePath() {
  std::wstring path(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!length || length >= path.size()) throw std::runtime_error("Cannot locate ETL.");
  path.resize(length);
  return path;
}

std::filesystem::path tempPath() {
  std::wstring path(32768, L'\0');
  const DWORD length = GetTempPathW(static_cast<DWORD>(path.size()), path.data());
  if (!length || length >= path.size()) throw std::runtime_error("Cannot locate the temporary folder.");
  path.resize(length);
  return std::filesystem::path(path).lexically_normal();
}

bool samePath(const std::filesystem::path& a, const std::filesystem::path& b) {
  return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}

bool installedClient(const std::filesystem::path& executable) {
  wchar_t location[32768]{};
  DWORD size = sizeof(location);
  const wchar_t* key = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{53C72D03-2FB4-47B7-B02A-661EB9A5B56E}_is1";
  if (RegGetValueW(HKEY_CURRENT_USER, key, L"InstallLocation", RRF_RT_REG_SZ,
      nullptr, location, &size) != ERROR_SUCCESS) return false;
  return samePath(std::filesystem::path(location) / executable.filename(), executable);
}

std::filesystem::path createStage() {
  GUID id{};
  wchar_t name[40]{};
  if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, name, 40))
    throw std::runtime_error("Cannot create the update folder.");
  const auto directory = tempPath() / (std::wstring(L"etl-update-") + name);
  if (!CreateDirectoryW(directory.c_str(), nullptr)) throw std::runtime_error("Cannot create the update folder.");
  return directory;
}

bool validStage(const std::filesystem::path& directory) {
  const auto name = directory.filename().wstring();
  if (name.size() != 49 || name.substr(0, 12) != L"etl-update-{" || name.back() != L'}') return false;
  GUID id{};
  if (FAILED(CLSIDFromString(name.substr(11).c_str(), &id))) return false;
  const auto attributes = GetFileAttributesW(directory.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
    !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) && samePath(directory.parent_path() / L".", tempPath() / L".");
}

DWORD request(const std::wstring& url, uint64_t limit, const std::atomic<bool>& cancelled,
  const std::function<void(const char*, DWORD)>& consume) {
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS)
    throw std::runtime_error("Invalid update URL.");
  const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
  std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
  if (parts.dwExtraInfoLength) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  const std::wstring agent = L"ETL/" + std::wstring(etlVersion, etlVersion + std::char_traits<char>::length(etlVersion));
  InternetHandle session{WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
  if (!session || !WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000))
    throw std::runtime_error("Cannot connect to GitHub. Try again later.");
  InternetHandle connection{WinHttpConnect(session, host.c_str(), parts.nPort, 0)};
  InternetHandle handle{connection ? WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr,
    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr};
  DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
  if (!handle || !WinHttpSetOption(handle, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)))
    throw std::runtime_error("Cannot connect to GitHub. Try again later.");
  const wchar_t* headers = host == L"api.github.com" ?
    L"Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2026-03-10\r\n" : L"Accept: application/octet-stream\r\n";
  const auto deadline = GetTickCount64() + 120000;
  if (cancelled || !WinHttpSendRequest(handle, headers, static_cast<DWORD>(-1),
      WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(handle, nullptr))
    throw std::runtime_error("Cannot connect to GitHub. Try again later.");
  DWORD status = 0, length = sizeof(status);
  if (!WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX))
    throw std::runtime_error("Invalid GitHub response.");
  if (status == 404) return status;
  if (status == 403 || status == 429) throw std::runtime_error("GitHub is busy. Try again later.");
  if (status != 200) throw std::runtime_error("GitHub could not provide the update. Try again later.");
  uint64_t total = 0;
  std::array<char, 16384> buffer{};
  while (!cancelled && GetTickCount64() < deadline) {
    DWORD read = 0;
    if (!WinHttpReadData(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read))
      throw std::runtime_error("The download was interrupted. Try again.");
    if (!read) return status;
    total += read;
    if (total > limit) throw std::runtime_error("The update exceeds its expected size.");
    consume(buffer.data(), read);
  }
  throw std::runtime_error(cancelled ? "Update cancelled." : "The download timed out. Try again.");
}

std::wstring quote(const std::filesystem::path& path) { return L"\"" + path.wstring() + L"\""; }

bool startProcess(const std::filesystem::path& executable, std::wstring arguments,
  HANDLE* process = nullptr, HANDLE parent = nullptr) {
  std::wstring command = quote(executable) + (arguments.empty() ? L"" : L" " + arguments);
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = parent ? sizeof(startup) : sizeof(STARTUPINFOW);
  std::vector<unsigned char> attributes;
  if (parent) {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    attributes.resize(size);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) return false;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        &parent, sizeof(parent), nullptr, nullptr)) {
      DeleteProcThreadAttributeList(startup.lpAttributeList); return false;
    }
  }
  PROCESS_INFORMATION info{};
  const bool ok = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, parent != nullptr,
    CREATE_NO_WINDOW | (parent ? EXTENDED_STARTUPINFO_PRESENT : 0), nullptr,
    executable.parent_path().c_str(), &startup.StartupInfo, &info) != FALSE;
  if (parent) DeleteProcThreadAttributeList(startup.lpAttributeList);
  if (!ok) return false;
  CloseHandle(info.hThread);
  if (process) *process = info.hProcess;
  else CloseHandle(info.hProcess);
  return true;
}
}

std::optional<UpdateRelease> parseUpdateRelease(const std::string& text, const std::string& current, bool installed) {
  const auto json = nlohmann::json::parse(text);
  if (!json.is_object() || !json.at("draft").is_boolean() || !json.at("prerelease").is_boolean())
    throw std::runtime_error("Invalid release metadata.");
  if (json.at("draft").get<bool>() || json.at("prerelease").get<bool>()) return std::nullopt;
  const auto tag = json.at("tag_name").get<std::string>();
  if (versionParts(tag) <= versionParts(current)) return std::nullopt;
  const auto version = tag.front() == 'v' ? tag.substr(1) : tag;
  const auto filename = installed ? "ETL-Setup-" + version + "-x64.exe" : "etl-client.exe";
  const auto expectedUrl = "https://github.com/5forzin/etl/releases/download/" + tag + "/" + filename;
  const auto& assets = json.at("assets");
  if (!assets.is_array()) throw std::runtime_error("Invalid release assets.");
  for (const auto& asset : assets) {
    if (asset.at("name").get<std::string>() != filename) continue;
    const auto digest = asset.at("digest").get<std::string>();
    const auto url = asset.at("browser_download_url").get<std::string>();
    if (asset.at("state") != "uploaded" || digest.substr(0, 7) != "sha256:" || !validHash(digest.substr(7)) ||
        !asset.at("size").is_number_unsigned() || !asset.at("size").get<uint64_t>() ||
        asset.at("size").get<uint64_t>() > maxDownload || url != expectedUrl)
      throw std::runtime_error("The release has no verified Windows download.");
    return UpdateRelease{version, url, digest.substr(7), asset.at("size").get<uint64_t>()};
  }
  throw std::runtime_error("The Windows download is not available yet.");
}

bool verifyUpdateFile(const std::filesystem::path& path, const std::string& sha256) {
  if (!validHash(sha256)) return false;
  std::ifstream file(path, std::ios::binary);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!file || !context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) return false;
  std::array<char, 16384> buffer{};
  while (file) {
    file.read(buffer.data(), buffer.size());
    if (file.gcount() && EVP_DigestUpdate(context.get(), buffer.data(), static_cast<size_t>(file.gcount())) != 1) return false;
  }
  if (!file.eof()) return false;
  unsigned char digest[EVP_MAX_MD_SIZE]{};
  unsigned length = 0;
  if (EVP_DigestFinal_ex(context.get(), digest, &length) != 1 || length != 32) return false;
  std::string actual;
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned i = 0; i < length; ++i) { actual += hex[digest[i] >> 4]; actual += hex[digest[i] & 15]; }
  return actual == sha256;
}

bool replacePortableUpdate(const std::filesystem::path& source, const std::filesystem::path& target,
  const std::filesystem::path& backup) {
  const auto replacement = std::filesystem::path(backup.wstring() + L".new");
  if (!CopyFileW(source.c_str(), replacement.c_str(), TRUE)) {
    DeleteFileW(replacement.c_str());
    return false;
  }
  if (!MoveFileExW(target.c_str(), backup.c_str(), MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(replacement.c_str());
    return false;
  }
  if (!MoveFileExW(replacement.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
    MoveFileExW(backup.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    DeleteFileW(replacement.c_str());
    return false;
  }
  DeleteFileW(backup.c_str());
  return true;
}

void cleanupUpdate(const std::filesystem::path& directory) {
  if (!validStage(directory)) return;
  for (int attempt = 0; attempt < 20; ++attempt) {
    DeleteFileW((directory / L"update.exe").c_str());
    DeleteFileW((directory / L"updater.exe").c_str());
    if (RemoveDirectoryW(directory.c_str())) return;
    Sleep(100);
  }
}

int applyUpdate(int argc, wchar_t** argv) {
  if (argc != 7) return 25;
  const std::filesystem::path directory(argv[3]), target(argv[4]);
  const std::wstring hashWide(argv[5]), mode(argv[6]);
  if (hashWide.size() != 64 || !std::all_of(hashWide.begin(), hashWide.end(), [](wchar_t ch) {
      return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
    })) return 25;
  std::string hash;
  for (const auto ch : hashWide) hash += static_cast<char>(ch);
  if (!validStage(directory) || !target.is_absolute() || !samePath(target.extension(), L".exe") ||
      !validHash(hash) || (mode != L"installed" && mode != L"portable")) return 25;
  wchar_t* end = nullptr;
  const auto value = _wcstoui64(argv[2], &end, 10);
  HANDLE parent = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
  if (!value || !end || *end || !GetProcessId(parent)) return 25;
  const DWORD wait = WaitForSingleObject(parent, 60000);
  CloseHandle(parent);
  if (wait != WAIT_OBJECT_0) return 25;
  const auto source = directory / L"update.exe";
  bool ok = verifyUpdateFile(source, hash);
  if (ok && mode == L"installed") {
    HANDLE installer = nullptr;
    ok = startProcess(source, L"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /DIR=" +
      quote(target.parent_path()), &installer);
    if (ok) {
      DWORD code = 1;
      ok = WaitForSingleObject(installer, INFINITE) == WAIT_OBJECT_0 && GetExitCodeProcess(installer, &code) && code == 0;
      CloseHandle(installer);
    }
  } else if (ok) {
    const auto backup = target.parent_path() / (target.filename().wstring() + L"." + directory.filename().wstring() + L".bak");
    ok = replacePortableUpdate(source, target, backup);
  }
  if (!ok) MessageBoxW(nullptr, L"The update could not be installed. ETL will reopen with your saved settings.", L"ETL", MB_OK | MB_ICONERROR);
  const bool restarted = startProcess(target, L"--cleanup-update " + quote(directory));
  if (!restarted) MessageBoxW(nullptr, L"ETL could not restart. Open it from its original location.", L"ETL", MB_OK | MB_ICONERROR);
  return ok && restarted ? 0 : 25;
}

UpdateClient::UpdateClient(std::string currentVersion) :
  currentVersion_(currentVersion.empty() ? etlVersion : std::move(currentVersion)),
  executable_(executablePath()), installed_(installedClient(executable_)) {}

UpdateClient::~UpdateClient() {
  cancelled_ = true;
  if (worker_.joinable()) worker_.join();
  if (!directory_.empty()) cleanupUpdate(directory_);
}

UpdateState UpdateClient::snapshot() { std::lock_guard<std::mutex> lock(mutex_); return state_; }

void UpdateClient::fail(const std::string& error) {
  std::lock_guard<std::mutex> lock(mutex_);
  state_.phase = UpdatePhase::Failed;
  state_.error = error;
}

void UpdateClient::check(bool manual) {
  const auto state = snapshot();
  if (state.phase == UpdatePhase::Checking || state.phase == UpdatePhase::Downloading || state.phase == UpdatePhase::Ready ||
      (!manual && (GetTickCount64() < nextCheck_ || state.offered))) return;
  if (worker_.joinable()) worker_.join();
  nextCheck_ = GetTickCount64() + checkInterval;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = {}; state_.phase = UpdatePhase::Checking;
    if (manual) dismissed_.clear();
  }
  worker_ = std::thread([this] {
    try {
      std::string json;
      const auto status = request(L"https://api.github.com/repos/5forzin/etl/releases/latest", 1024 * 1024, cancelled_,
        [&](const char* data, DWORD size) { json.append(data, size); });
      const auto release = status == 404 ? std::nullopt : parseUpdateRelease(json, currentVersion_, installed_);
      std::lock_guard<std::mutex> lock(mutex_);
      release_ = release;
      state_.phase = release ? UpdatePhase::Available : UpdatePhase::Current;
      if (release) { state_.version = release->version; state_.offered = state_.version != dismissed_; }
    } catch (const nlohmann::json::exception&) { fail("GitHub returned invalid release metadata."); }
      catch (const std::exception& error) { fail(error.what()); }
  });
}

void UpdateClient::dismiss() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (state_.phase == UpdatePhase::Downloading || state_.phase == UpdatePhase::Ready) return;
  dismissed_ = state_.version; state_.offered = false;
}

void UpdateClient::download() {
  const auto state = snapshot();
  if (!release_ || !state.offered || state.phase == UpdatePhase::Downloading || state.phase == UpdatePhase::Ready) return;
  if (worker_.joinable()) worker_.join();
  if (!directory_.empty()) { cleanupUpdate(directory_); directory_.clear(); }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.phase = UpdatePhase::Downloading; state_.error.clear(); state_.progress = 0;
  }
  const auto release = *release_;
  worker_ = std::thread([this, release] {
    try {
      directory_ = createStage();
      const auto path = directory_ / L"update.exe";
      std::ofstream file(path, std::ios::binary);
      if (!file) throw std::runtime_error("Cannot save the update. Check free disk space.");
      uint64_t total = 0;
      const std::wstring url(release.url.begin(), release.url.end());
      const auto status = request(url, release.size, cancelled_, [&](const char* data, DWORD size) {
        file.write(data, size);
        if (!file) throw std::runtime_error("Cannot save the update. Check free disk space.");
        total += size;
        std::lock_guard<std::mutex> lock(mutex_);
        state_.progress = static_cast<float>(total) / static_cast<float>(release.size);
      });
      file.close();
      if (status != 200 || total != release.size || !verifyUpdateFile(path, release.sha256))
        throw std::runtime_error("The download could not be verified. Try again.");
      std::lock_guard<std::mutex> lock(mutex_);
      state_.phase = UpdatePhase::Ready; state_.progress = 1;
    } catch (const std::exception& error) { fail(error.what()); }
  });
}

bool UpdateClient::launch() {
  if (snapshot().phase != UpdatePhase::Ready || !release_) return false;
  if (worker_.joinable()) worker_.join();
  const auto helper = directory_ / L"updater.exe";
  if (!CopyFileW(executable_.c_str(), helper.c_str(), TRUE)) { fail("Cannot start the updater. Try again."); return false; }
  HANDLE parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, GetCurrentProcessId());
  const std::wstring hash(release_->sha256.begin(), release_->sha256.end());
  const auto arguments = L"--apply-update " + std::to_wstring(reinterpret_cast<uintptr_t>(parent)) + L" " +
    quote(directory_) + L" " + quote(executable_) + L" " + hash + (installed_ ? L" installed" : L" portable");
  const bool ok = parent && startProcess(helper, arguments, nullptr, parent);
  if (parent) CloseHandle(parent);
  if (!ok) { DeleteFileW(helper.c_str()); fail("Cannot start the updater. Try again."); return false; }
  directory_.clear(); // The restarted client owns cleanup after the helper exits.
  return true;
}
