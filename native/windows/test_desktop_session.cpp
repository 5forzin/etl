#include "desktop_session.h"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>

static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

static bool until(const std::function<bool()>& done) {
  const ULONGLONG end = GetTickCount64() + 3000;
  while (!done() && GetTickCount64() < end) Sleep(10);
  return done();
}

static std::filesystem::path utf8Path(const std::string& value) {
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  std::wstring path(size, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), path.data(), size);
  return path;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 4 && std::wstring(argv[1]) == L"--desktop-full") {
    FullSessionWorker worker;
    if (!worker.open(argv[2], std::wcstoul(argv[3], nullptr, 10))) return 2;
    const auto configuration = worker.configuration();
    if (configuration == "failure") { worker.publish(SessionPhase::Failed, "Authentication failed."); return 4; }
    if (configuration == "crash") ExitProcess(17);
    if (configuration != "cancel") {
      worker.traffic(3, 100, 200, 1);
      worker.publish(SessionPhase::Running);
    }
    if (!worker.wait(5000)) return 3;
    if (configuration.rfind("orphan|", 0) == 0)
      std::ofstream(utf8Path(configuration.substr(7))) << "restored";
    worker.publish(SessionPhase::Stopped);
    return 0;
  }
  if (argc == 3 && std::wstring(argv[1]) == L"--orphan-parent") {
    FullSession session;
    std::wstring error;
    const auto encoded = std::filesystem::path(argv[2]).u8string();
    const std::string marker(encoded.begin(), encoded.end());
    if (!session.start("orphan|" + marker, error, nullptr, false)) return 4;
    if (!until([&] { return session.snapshot().phase == SessionPhase::Running; })) return 5;
    ExitProcess(0); // Deliberately bypass RAII to exercise parent-death detection.
  }
  try {
    FullSession session;
    std::wstring error;
    require(session.start("normal", error, nullptr, false), "worker launch failed");
    require(until([&] { return session.snapshot().phase == SessionPhase::Running; }), "worker did not become active");
    const auto active = session.snapshot();
    require(active.sessions == 3 && active.sent == 100 && active.received == 200 && active.failures == 1,
      "traffic counters did not cross the process boundary");
    require(!session.start("duplicate", error, nullptr, false), "duplicate start was accepted");
    session.requestStop();
    require(until([&] { return session.finished(); }), "worker did not stop");
    require(session.snapshot().phase == SessionPhase::Stopped, "normal stop was reported as failure");
    session.reset();

    require(session.start("cancel", error, nullptr, false), "cancel fixture failed");
    session.requestStop();
    require(until([&] { return session.finished(); }), "startup cancellation did not stop the worker");
    require(session.snapshot().phase == SessionPhase::Stopped, "startup cancellation was reported as failure");
    session.reset();

    require(session.start("failure", error, nullptr, false), "failure fixture failed");
    require(until([&] { return session.finished(); }), "failure fixture did not exit");
    require(session.snapshot().error == "Authentication failed.", "worker error was lost");
    session.reset();

    require(session.start("crash", error, nullptr, false), "crash fixture failed");
    require(until([&] { return session.finished(); }), "crash fixture did not exit");
    require(session.snapshot().phase == SessionPhase::Failed && !session.snapshot().error.empty(),
      "unexpected worker exit was reported as connected");
    session.reset();
    require(!session.start(std::string(9000, 'x'), error, nullptr, false), "oversized config was accepted");
    FullSessionWorker invalid;
    require(!invalid.open(L"invalid/session", GetCurrentProcessId()), "invalid session identifier was accepted");

    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const auto marker = std::filesystem::temp_directory_path() /
      (L"etl-parent-recovery-" + std::to_wstring(GetCurrentProcessId()) + L".txt");
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --orphan-parent \"" + marker.wstring() + L"\"";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    require(CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
      nullptr, nullptr, &startup, &process), "parent fixture failed");
    const bool exited = WaitForSingleObject(process.hProcess, 4000) == WAIT_OBJECT_0;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    require(exited && until([&] { return std::filesystem::exists(marker); }), "parent death did not trigger cleanup");
    std::filesystem::remove(marker);
    std::cout << "Desktop session lifecycle passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
