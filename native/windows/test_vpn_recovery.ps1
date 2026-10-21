param(
  [Parameter(Mandatory)][string]$ExecutablePath,
  [Parameter(Mandatory)][string]$Server,
  [Parameter(Mandatory)][string]$TokenPath,
  [Parameter(Mandatory)][string]$OutputPath,
  [int]$ServerPort = 443,
  [int]$LocalPort = 1082
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this integration test as administrator with no active ETL VPN.'
}
$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
$tokenFile = (Resolve-Path -LiteralPath $TokenPath).Path
$output = [IO.Path]::GetFullPath($OutputPath)
$directory = Split-Path -Parent $output
[IO.Directory]::CreateDirectory($directory) | Out-Null
$client = $null
$rule = 'ETL recovery test ' + [Guid]::NewGuid().ToString('N')
$results = [Collections.Generic.List[object]]::new()
$endpoint = ([Net.Dns]::GetHostAddresses($Server) | Where-Object {
  $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
} | Select-Object -First 1).IPAddressToString
if (!$endpoint) { throw 'Cannot resolve the ETL IPv4 endpoint.' }
$baselineDns = Get-DnsClientServerAddress | Where-Object InterfaceAlias -ne 'ETL' |
  Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress

function Test-EtlRoutes {
  return @(Get-NetRoute -InterfaceAlias ETL -ErrorAction SilentlyContinue | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1','100.64.0.0/10')
  }).Count -ne 0
}
function Wait-Until([scriptblock]$Check, [string]$Message, [int]$Seconds = 30) {
  $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
  do {
    if (& $Check) { return }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $deadline)
  throw $Message
}
function Assert-NormalNetwork {
  Wait-Until { !(Test-EtlRoutes) } 'ETL routes were not removed.'
  $dns = Get-DnsClientServerAddress | Where-Object InterfaceAlias -ne 'ETL' |
    Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress
  if ($dns -ne $baselineDns) { throw 'Physical DNS configuration changed.' }
  & curl.exe --noproxy '*' --silent --show-error --fail --connect-timeout 6 --max-time 12 --output NUL 'https://example.com'
  if ($LASTEXITCODE -ne 0) { throw 'Normal HTTPS connection was not restored.' }
}
function Start-Etl([string]$Credential = $tokenFile) {
  $arguments = '--headless --server ' + $Server + ' --server-port ' + $ServerPort +
    ' --port ' + $LocalPort + ' --token-file "' + $Credential + '" --connect-timeout-ms 4000 --vpn 1'
  $script:client = Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -PassThru `
    -RedirectStandardError (Join-Path $directory 'recovery-stderr.log') `
    -RedirectStandardOutput (Join-Path $directory 'recovery-stdout.log')
  $null = $script:client.Handle
}
function Start-HealthyEtl {
  Start-Etl
  Wait-Until {
    $script:client.Refresh()
    if ($script:client.HasExited) { throw 'ETL exited during startup.' }
    $routes = @(Get-NetRoute -InterfaceAlias ETL -ErrorAction SilentlyContinue | Where-Object {
      $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1','100.64.0.0/10')
    })
    $dns = @(Get-DnsClientServerAddress -InterfaceAlias ETL -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $routes.Count -eq 5 -and $dns -contains '198.18.0.2'
  } 'Full mode did not start.'
  & curl.exe --noproxy '*' --silent --show-error --fail --connect-timeout 6 --max-time 12 --output NUL 'https://example.com' 2> (Join-Path $directory 'recovery-https.log')
  if ($LASTEXITCODE -ne 0) { throw 'Full mode could not relay HTTPS.' }
}
function Assert-Recovered([string]$Scenario, [Diagnostics.Stopwatch]$Timer, [bool]$RequireFailureCode = $true) {
  Wait-Until { $script:client.Refresh(); $script:client.HasExited } 'ETL did not exit after tunnel failure.'
  $script:client.WaitForExit()
  if ($RequireFailureCode -and $script:client.ExitCode -ne 5) {
    throw ('Unexpected recovery exit code: ' + $script:client.ExitCode)
  }
  Assert-NormalNetwork
  $results.Add(@{scenario=$Scenario;restored=$true;durationMs=$Timer.ElapsedMilliseconds})
  $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output -Encoding UTF8
  $script:client = $null
}
try {
  if (Test-EtlRoutes) { throw 'Stop the active ETL VPN before running this test.' }
  Assert-NormalNetwork
  $invalidToken = Join-Path $directory 'invalid.token'
  [IO.File]::WriteAllText($invalidToken, ('a' * 64))
  try {
    Start-Etl $invalidToken
    Wait-Until { $client.Refresh(); $client.HasExited } 'Authentication preflight did not finish.' 12
    $client.WaitForExit()
    if ($client.ExitCode -ne 4 -or (Test-EtlRoutes)) {
      throw ('Unexpected preflight result: exit=' + $client.ExitCode + '; routes=' + (Test-EtlRoutes))
    }
    Assert-NormalNetwork
    $results.Add(@{scenario='invalid authentication before routes';restored=$true})
    $client = $null
  } finally { Remove-Item -LiteralPath $invalidToken -Force }

  Start-HealthyEtl
  # The route already installed by ETL identifies the pinned endpoint even
  # when mapdns is answering the system resolver with synthetic addresses.
  $endpoint = (Get-NetRoute -AddressFamily IPv4 | Where-Object {
    $_.DestinationPrefix -eq ($endpoint + '/32') -and $_.InterfaceAlias -ne 'ETL'
  } | Select-Object -First 1).DestinationPrefix -replace '/32$', ''
  if (!$endpoint) { throw 'Cannot identify the pinned ETL endpoint.' }
  try {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program $executable `
      -Protocol TCP -RemoteAddress $endpoint -RemotePort $ServerPort | Out-Null
    Assert-Recovered 'remote TLS transport blocked while engine stays alive' $timer
  } finally { Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule }

  Start-HealthyEtl
  $engine = Get-CimInstance Win32_Process -Filter "Name='hev-socks5-tunnel.exe'" |
    Where-Object ParentProcessId -eq $client.Id
  if (!$engine) { throw 'Cannot find the ETL-owned engine.' }
  $timer = [Diagnostics.Stopwatch]::StartNew()
  Stop-Process -Id $engine.ProcessId -Force
  Assert-Recovered 'TUN engine exit' $timer

  Start-HealthyEtl
  $timer = [Diagnostics.Stopwatch]::StartNew()
  Stop-Process -Id $client.Id -Force
  Assert-Recovered 'parent crash and restoration guard' $timer $false
} catch {
  $results.Add(@{restored=$false;error=$_.Exception.Message})
  $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output -Encoding UTF8
  throw
} finally {
  Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if ($client -and !$client.HasExited) { Stop-Process -Id $client.Id -Force }
}
