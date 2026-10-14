#include "updater.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <objbase.h>
#include <array>
#include <fstream>
#include <iostream>
#include <stdexcept>

using nlohmann::json;

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

static json release(const std::string& version = "0.4.0") {
  const auto asset = [&](const std::string& name) {
    return json{{"name", name}, {"state", "uploaded"}, {"size", 3},
      {"digest", "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"browser_download_url", "https://github.com/5forzin/etl/releases/download/v" + version + "/" + name}};
  };
  return {{"tag_name", "v" + version}, {"draft", false}, {"prerelease", false},
    {"assets", json::array({asset("etl-client.exe"), asset("ETL-Setup-" + version + "-x64.exe")})}};
}

static void rejects(const json& metadata) {
  bool rejected = false;
  try { parseUpdateRelease(metadata.dump(), "0.3.0", false); }
  catch (const std::exception&) { rejected = true; }
  require(rejected, "Invalid release metadata was accepted");
}

static std::filesystem::path selfPath() {
  wchar_t path[32768]{};
  require(GetModuleFileNameW(nullptr, path, 32768) != 0, "Cannot locate test executable");
  return path;
}

static void handoff(const std::filesystem::path& directory, bool installed) {
  GUID id{}; wchar_t name[40]{}, temporary[MAX_PATH]{};
  require(SUCCEEDED(CoCreateGuid(&id)) && StringFromGUID2(id, name, 40) && GetTempPathW(MAX_PATH, temporary), "Cannot create handoff stage");
  const auto stage = std::filesystem::path(temporary) / (std::wstring(L"etl-update-") + name);
  require(std::filesystem::create_directory(stage), "Cannot create handoff stage");
  const auto folder = directory / (installed ? L"installed client" : L"portable client");
  std::filesystem::create_directory(folder);
  const auto target = folder / (installed ? L"etl-client.exe" : L"ETL-Client.EXE");
  const auto helper = stage / L"updater.exe", source = stage / L"update.exe";
  std::filesystem::copy_file(selfPath(), target);
  std::filesystem::copy_file(selfPath(), helper);
  std::filesystem::copy_file(selfPath(), source);
  std::ifstream file(source, std::ios::binary);
  const std::string data(std::istreambuf_iterator<char>(file), {});
  std::array<unsigned char, 32> digest{};
  unsigned length = 0;
  require(EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1 && length == 32, "Cannot hash handoff fixture");
  std::wstring hash;
  constexpr wchar_t hex[] = L"0123456789abcdef";
  for (const auto byte : digest) { hash += hex[byte >> 4]; hash += hex[byte & 15]; }
  file.close();
  STARTUPINFOW startup{}; startup.cb = sizeof(startup);
  PROCESS_INFORMATION sleeper{}, updater{};
  auto command = L"\"" + target.wstring() + L"\" --wait-update";
  require(CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
    nullptr, folder.c_str(), &startup, &sleeper), "Cannot start old-client fixture");
  CloseHandle(sleeper.hThread);
  require(SetHandleInformation(sleeper.hProcess, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT), "Cannot inherit parent handle");
  command = L"\"" + helper.wstring() + L"\" --apply-update " +
    std::to_wstring(reinterpret_cast<uintptr_t>(sleeper.hProcess)) + L" \"" + stage.wstring() + L"\" \"" +
    target.wstring() + L"\" " + hash + (installed ? L" installed" : L" portable");
  require(CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
    nullptr, stage.c_str(), &startup, &updater), "Cannot start updater fixture");
  CloseHandle(updater.hThread);
  require(WaitForSingleObject(updater.hProcess, 15000) == WAIT_OBJECT_0, "Updater handoff timed out");
  DWORD code = 1;
  require(GetExitCodeProcess(updater.hProcess, &code) && code == 0, "Updater handoff failed");
  CloseHandle(updater.hProcess); CloseHandle(sleeper.hProcess);
  for (int i = 0; i < 50 && !std::filesystem::exists(folder / L"restarted.txt"); ++i) Sleep(50);
  require(std::filesystem::exists(folder / L"restarted.txt"), "Updated client did not restart");
  require(!std::filesystem::exists(stage), "Restart did not clean the staging directory");
  if (installed) require(std::filesystem::exists(folder / L"installed.txt"), "Installer did not receive the original installation directory");
  Sleep(100);
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--wait-update") { Sleep(500); return 0; }
  if (argc == 3 && std::string(argv[1]) == "--cleanup-update") {
    cleanupUpdate(std::filesystem::path(argv[2]));
    std::ofstream(selfPath().parent_path() / L"restarted.txt") << "restarted";
    return 0;
  }
  if (argc == 7 && std::string(argv[1]) == "--apply-update") {
    std::array<std::wstring, 7> values;
    std::array<wchar_t*, 7> wide{};
    for (size_t i = 0; i < wide.size(); ++i) { values[i] = std::filesystem::path(argv[i]).wstring(); wide[i] = values[i].data(); }
    return applyUpdate(argc, wide.data());
  }
  if (argc > 1 && std::string(argv[1]) == "/VERYSILENT") {
    for (int i = 2; i < argc; ++i) {
      const std::string argument(argv[i]);
      if (argument.rfind("/DIR=", 0) == 0) {
        std::ofstream(std::filesystem::path(argument.substr(5)) / L"installed.txt") << "installed";
        return 0;
      }
    }
    return 1;
  }
  if (argc == 2 && std::string(argv[1]) == "--github") {
    UpdateClient updater("0.0.0"); updater.check();
    for (int i = 0; i < 120 && updater.snapshot().phase == UpdatePhase::Checking; ++i) Sleep(250);
    const auto state = updater.snapshot();
    if (state.phase != UpdatePhase::Available) {
      std::cerr << "Live GitHub check failed: " << state.error << '\n'; return 1;
    }
    updater.download();
    for (int i = 0; i < 500 && updater.snapshot().phase == UpdatePhase::Downloading; ++i) Sleep(250);
    const auto downloaded = updater.snapshot();
    if (downloaded.phase != UpdatePhase::Ready) {
      std::cerr << "Live GitHub asset verification failed: " << downloaded.error << '\n'; return 1;
    }
    std::cout << "Live GitHub HTTPS asset download and SHA-256 verification passed; no installation performed.\n";
    return 0;
  }
  std::filesystem::path directory;
  bool ownsDirectory = false;
  try {
    const auto metadata = release();
    const auto portable = parseUpdateRelease(metadata.dump(), "0.3.0", false);
    const auto installed = parseUpdateRelease(metadata.dump(), "0.3.0", true);
    require(portable && portable->url.find("etl-client.exe") != std::string::npos, "Portable asset selection failed");
    require(installed && installed->url.find("ETL-Setup-0.4.0-x64.exe") != std::string::npos, "Installer asset selection failed");
    require(!parseUpdateRelease(metadata.dump(), "0.4.0", false), "Equal version prompted an update");
    require(!parseUpdateRelease(metadata.dump(), "1.0.0", false), "Downgrade was offered");
    require(parseUpdateRelease(release("0.10.0").dump(), "0.9.0", false).has_value(), "Version comparison was lexicographic");
    auto invalid = metadata;
    invalid["prerelease"] = true;
    require(!parseUpdateRelease(invalid.dump(), "0.3.0", false), "Prerelease was offered");
    invalid = metadata; invalid["draft"] = true;
    require(!parseUpdateRelease(invalid.dump(), "0.3.0", false), "Draft was offered");
    for (const auto* version : {"v0.4", "v0.4.0-rc.1", "v00.4.0", "v0.4.0.1", "v4294967296.0.0", "", "v0.4.-1"}) {
      invalid = metadata; invalid["tag_name"] = version; rejects(invalid);
    }
    for (const auto* url : {"http://github.com/5forzin/etl/releases/download/v0.4.0/etl-client.exe",
        "https://github.com/another/etl/releases/download/v0.4.0/etl-client.exe",
        "https://example.com/etl-client.exe", "https://github.com/5forzin/etl/releases/download/v0.3.0/etl-client.exe"}) {
      invalid = metadata; invalid["assets"][0]["browser_download_url"] = url; rejects(invalid);
    }
    invalid = metadata; invalid["assets"][0]["digest"] = nullptr; rejects(invalid);
    invalid = metadata; invalid["assets"][0]["digest"] = "sha256:bad"; rejects(invalid);
    invalid = metadata; invalid["assets"][0]["size"] = -1; rejects(invalid);
    invalid = metadata; invalid["assets"][0]["size"] = 0; rejects(invalid);
    invalid = metadata; invalid["assets"][0]["size"] = 129 * 1024 * 1024; rejects(invalid);
    invalid = metadata; invalid["assets"][0]["state"] = "new"; rejects(invalid);
    invalid = metadata; invalid["assets"] = json::array(); rejects(invalid);
    invalid = metadata; invalid["assets"] = "invalid"; rejects(invalid);
    rejects(json::array()); rejects(json{{"tag_name", "v0.4.0"}});
    bool malformed = false;
    try { parseUpdateRelease("{broken", "0.3.0", false); }
    catch (const std::exception&) { malformed = true; }
    require(malformed, "Malformed JSON was accepted");

    wchar_t temporary[MAX_PATH]{};
    require(GetTempPathW(MAX_PATH, temporary) != 0, "No temporary directory");
    directory = std::filesystem::path(temporary) / (L"etl-update-tests-" + std::to_wstring(GetCurrentProcessId()));
    require(std::filesystem::create_directory(directory), "Cannot create test directory");
    ownsDirectory = true;
    const auto source = directory / L"source.exe", target = directory / L"target.exe", backup = directory / L"backup.exe";
    { std::ofstream file(source, std::ios::binary); file << "abc"; }
    require(verifyUpdateFile(source, portable->sha256), "Valid download failed verification");
    require(!verifyUpdateFile(source, std::string(64, '0')), "Incorrect digest was accepted");
    require(!verifyUpdateFile(directory / L"missing.exe", portable->sha256), "Missing download was accepted");
    { std::ofstream file(source, std::ios::binary | std::ios::app); file << "d"; }
    require(!verifyUpdateFile(source, portable->sha256), "Tampered download was accepted");
    { std::ofstream file(source, std::ios::binary); file << "abc"; }
    { std::ofstream file(target, std::ios::binary); file << "old"; }
    require(!replacePortableUpdate(directory / L"missing.exe", target, backup), "Missing source installed successfully");
    { std::ifstream file(target); std::string text; file >> text; require(text == "old", "Failed update did not restore original"); }
    require(!std::filesystem::exists(backup), "Rollback left a backup behind");
    HANDLE locked = CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    require(locked != INVALID_HANDLE_VALUE, "Cannot lock replacement target");
    const bool replacedLocked = replacePortableUpdate(source, target, backup);
    CloseHandle(locked);
    require(!replacedLocked, "Running executable was replaced");
    require(!std::filesystem::exists(std::filesystem::path(backup.wstring() + L".new")), "Failed replacement left temporary data");
    { std::ifstream file(target); std::string text; file >> text; require(text == "old", "Locked executable was modified"); }
    require(replacePortableUpdate(source, target, backup), "Portable replacement failed");
    require(verifyUpdateFile(target, portable->sha256), "Portable replacement corrupted the executable");
    require(!std::filesystem::exists(backup), "Successful update left a backup behind");
    cleanupUpdate(directory);
    require(std::filesystem::exists(target), "Cleanup accepted an unrelated directory");
    handoff(directory, false);
    handoff(directory, true);
    std::filesystem::remove_all(directory);
    std::cout << "Release selection, version ordering, integrity, rollback, portable and installer handoffs passed.\n";
    return 0;
  } catch (const std::exception& error) {
    if (ownsDirectory) std::filesystem::remove_all(directory);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
