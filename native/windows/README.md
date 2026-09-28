# Windows portable client

Download `etl-client.exe`, `SHA256SUMS`, and `LICENSE-OpenSSL.txt` from the [GitHub release](https://github.com/5forzin/etl/releases). The portable build is a single Windows x64 executable; it needs no installer or MSYS2 DLLs. It is not code-signed. Verify the checksum with `Get-FileHash .\etl-client.exe -Algorithm SHA256` before running it.

The client opens in the system tray. Enter the ETL server, port, and token directly, then connect. The token field is masked. It listens only on `127.0.0.1`. The same local port accepts SOCKS5 and HTTP proxy requests: use `socks5h://127.0.0.1:1080` for SOCKS5 or `http://127.0.0.1:1080` in ZCode's **Settings → General → HTTP Proxy** field, then restart ZCode. HTTP `CONNECT` and ordinary absolute-form HTTP requests are supported. It forwards TCP only. Settings are stored in `%APPDATA%\ETL\settings.ini`; the token is stored there encrypted with Windows DPAPI for the current user, never as plaintext or in the release. An existing `token_file` setting is migrated automatically when the file is available. The headless test mode still accepts `--token-file`.

The optional **Servidor reserva**, **Porta reserva** and masked **Token reserva**
fields configure automatic failover for new connections. Use `etl2.nora.systems`
as the backup for `etl.nora.systems`, with the backup server's own ETL token.
An empty backup token reuses the primary token; an empty backup host disables
failover. Both credentials are stored with Windows DPAPI. **Timeout (ms)** defaults
to `1000` and covers DNS, TCP, verified TLS and authentication for each host.
Existing streams keep their normal idle timeout and do not migrate or replay data.

Headless mode accepts `--fallback-server`, `--fallback-port`,
`--fallback-token-file` and `--connect-timeout-ms`. See the
[connection guide](../../docs/getting-started.md#automatic-backup-host) for the
equivalent Node.js options. CI builds and tests a portable Windows artifact.

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
