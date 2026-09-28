# Windows portable client

Download `etl-client.exe`, `SHA256SUMS`, and `LICENSE-OpenSSL.txt` from the [GitHub release](https://github.com/5forzin/etl/releases). The portable build is a single Windows x64 executable; it needs no installer or MSYS2 DLLs. It is not code-signed. Verify the checksum with `Get-FileHash .\etl-client.exe -Algorithm SHA256` before running it.

The client opens in the system tray. Enter the ETL server, port, and token directly, then connect. The token field is masked. It listens only on `127.0.0.1`; configure an application to use SOCKS5 at `127.0.0.1:1080` with proxy-side DNS. It forwards TCP only. Settings are stored in `%APPDATA%\ETL\settings.ini`; the token is stored there encrypted with Windows DPAPI for the current user, never as plaintext or in the release. An existing `token_file` setting is migrated automatically when the file is available. The headless test mode still accepts `--token-file`.

To reproduce the portable build with MSYS2 UCRT64 (`gcc`, `openssl`, `cmake`, `ninja`):

```powershell
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
cmake -S native/windows -B build/windows-portable -G Ninja -DCMAKE_BUILD_TYPE=Release -DETL_PORTABLE=ON
cmake --build build/windows-portable
.\native\windows\package.ps1 -Portable
$env:ETL_NATIVE_CLIENT = (Resolve-Path .\dist\windows-portable\etl-client.exe).Path
node --test test/native-client.test.js
```

The package script checks that the EXE has no MSYS2 runtime DLL imports and writes `dist/windows-portable/SHA256SUMS`.
