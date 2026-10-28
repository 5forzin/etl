#pragma once
#include <filesystem>
#include <string>

bool localProxyAvailable(int port);
bool openProxyBrowser(int port, std::wstring& error);
bool startProxyBrowser(const std::filesystem::path& executable,
  const std::filesystem::path& profile, int port, std::wstring& error);
