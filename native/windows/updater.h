#pragma once
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

enum class UpdatePhase { Idle, Checking, Current, Available, Downloading, Ready, Failed };

struct UpdateState {
  UpdatePhase phase = UpdatePhase::Idle;
  std::string version, error;
  float progress = 0;
  bool offered = false;
};

struct UpdateRelease {
  std::string version, url, sha256;
  uint64_t size = 0;
};

std::optional<UpdateRelease> parseUpdateRelease(const std::string& json, const std::string& current, bool installed);
bool verifyUpdateFile(const std::filesystem::path& path, const std::string& sha256);
bool replacePortableUpdate(const std::filesystem::path& source, const std::filesystem::path& target,
  const std::filesystem::path& backup);
int applyUpdate(int argc, wchar_t** argv);
void cleanupUpdate(const std::filesystem::path& directory);

class UpdateClient {
 public:
  explicit UpdateClient(std::string currentVersion = {});
  ~UpdateClient();
  UpdateState snapshot();
  void check(bool manual = false);
  void dismiss();
  void download();
  bool launch();
 private:
  void fail(const std::string& error);
  std::mutex mutex_;
  std::thread worker_;
  std::atomic<bool> cancelled_{false};
  UpdateState state_;
  std::optional<UpdateRelease> release_;
  std::string dismissed_;
  std::string currentVersion_;
  std::filesystem::path executable_, directory_;
  bool installed_ = false;
  uint64_t nextCheck_ = 0;
};
