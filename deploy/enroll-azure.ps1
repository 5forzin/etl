param(
  [Parameter(Mandatory)][string]$ResourceGroup,
  [Parameter(Mandatory)][string]$VMName,
  [Parameter(Mandatory)][string]$TokenPath
)
$ErrorActionPreference = 'Stop'
if ($ResourceGroup -notmatch '^[a-zA-Z0-9_.()-]+$' -or $VMName -notmatch '^[a-zA-Z0-9_-]+$') {
  throw 'Invalid Azure resource name'
}
$target = [IO.Path]::GetFullPath($TokenPath)
if (Test-Path -LiteralPath $target) { throw 'Token file already exists; refusing to overwrite it' }
$parent = Split-Path -Parent $target
if (-not (Test-Path -LiteralPath $parent)) { throw 'Create the private destination directory first' }
$subscription = (az account show --query id -o tsv).Trim()
if ($LASTEXITCODE -ne 0 -or $subscription -notmatch '^[a-fA-F0-9-]{36}$') { throw 'Cannot resolve Azure subscription' }
$accessToken = (az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot obtain Azure access token' }
$rsa = [Security.Cryptography.RSA]::Create(2048)
try {
  $publicKey = [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo())
  # Only ciphertext reaches the Azure Run Command output and activity history.
  $script = @'
set -eu
umask 077
etl_pub=$(mktemp)
trap 'rm -f "$etl_pub"' EXIT
printf '%s' '__PUBLIC_KEY__' | base64 -d > "$etl_pub"
openssl pkeyutl -encrypt -pubin -inkey "$etl_pub" -keyform DER -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in /opt/etl/secrets/token | base64 -w 0
'@.Replace('__PUBLIC_KEY__', $publicKey)
  $headers = @{ Authorization = "Bearer $accessToken" }
  $uri = "https://management.azure.com/subscriptions/$subscription/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$VMName/runCommand?api-version=2024-11-01"
  $body = @{ commandId = 'RunShellScript'; script = @($script) } | ConvertTo-Json -Depth 4
  $response = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -ContentType application/json -Body $body
  $location = $response.Headers.Location | Select-Object -First 1
  if (-not $location -or ([uri]$location).Host -ne 'management.azure.com') {
    throw 'Azure did not return a trusted polling URL'
  }
  $result = $null
  for ($attempt = 0; $attempt -lt 120; $attempt++) {
    Start-Sleep -Seconds 5
    $poll = Invoke-WebRequest -Uri $location -Headers $headers
    if ($poll.StatusCode -eq 200 -and $poll.Content) {
      $result = $poll.Content | ConvertFrom-Json
      break
    }
  }
  if (-not $result) { throw 'Timed out waiting for Azure Run Command' }
  $stdout = $result.value.message -join "`n"
  $match = [regex]::Match($stdout, '(?m)^[A-Za-z0-9+/]{342}==$')
  if (-not $match.Success) { throw 'No encrypted token received; check server provisioning' }
  $plaintext = $rsa.Decrypt([Convert]::FromBase64String($match.Value), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  $token = [Text.Encoding]::UTF8.GetString($plaintext).Trim()
  if ($token -notmatch '^[a-f0-9]{64}$') { throw 'Invalid decrypted token' }
  $stream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $bytes = [Text.Encoding]::ASCII.GetBytes($token + "`n"); $stream.Write($bytes, 0, $bytes.Length) }
  finally { $stream.Dispose() }
  if ($IsWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    icacls $target /inheritance:r /grant:r "${identity}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict token file permissions' }
  } else {
    [IO.File]::SetUnixFileMode($target, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
  }
  Write-Output "ETL client token saved privately to $target"
} finally {
  $rsa.Dispose()
  $accessToken = $null
  $token = $null
  $plaintext = $null
}
