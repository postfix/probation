<#
.SYNOPSIS
  Install, upgrade or remove Probation as a Windows service (docs/operations.md, "Native service").
.DESCRIPTION
  install    first install: creates only what is absent, registers the service, starts it
  upgrade    stop, keep the old files as .prev, install the new ones, validate, start and check it stays up, else roll back
  uninstall  stop and delete the service, remove only what install created and recorded
  Never replaces an existing config.toml, blocklist, TLS file, key or data. The service runs as the virtual account
  NT SERVICE\Probation (no password is stored): it can read the configuration and change only its data and log directories.
  Security model: C:\ProgramData lets any user create folders, so every directory this script uses is created BY it with a
  protected ACL (SYSTEM and Administrators, then the service account) BEFORE anything is written into it, and a directory or file
  that already exists is used only if it is owned by Administrators or SYSTEM and is not a junction or other reparse point.
  Uninstall removes only paths this script computes itself, only when the record names them and this install created them.
  Package-manager registry URLs and credential entries are touched only with -ConfigureTools, and then only the lines this
  script owns. Run from an elevated PowerShell (5.1 or 7).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)][ValidateSet('install', 'upgrade', 'uninstall')][string]$Action,
  [string]$Binary,
  [string]$ConfigDir = (Join-Path $env:ProgramData 'Probation\config'),
  [string]$DataDir = (Join-Path $env:ProgramData 'Probation\data'),
  [string]$LogDir = (Join-Path $env:ProgramData 'Probation\log'),
  [string]$BinDir = (Join-Path $env:ProgramFiles 'Probation'),
  [string]$Listen = '127.0.0.1:8080',
  [string]$PublicUrl,
  [string]$TlsCert,
  [string]$TlsKey,
  [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$Name = 'Probation',
  [switch]$NoStart,
  [switch]$NoVerify,
  [switch]$DevPackage,
  [string]$CosignBundle,
  [switch]$ConfigureTools,
  [string]$NpmRc,
  [string]$PipIni = (Join-Path $env:ProgramData 'pip\pip.ini')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Res = if (Test-Path (Join-Path $Here 'deploy')) { $Here } else { Split-Path -Parent $Here }
if (-not $Binary) { $Binary = Join-Path $Here 'probation.exe' }
$BinPath = Join-Path $BinDir 'probation.exe'
$ConfigFile = Join-Path $ConfigDir 'config.toml'
$Blocklist = Join-Path $ConfigDir 'blocklist.json'
$Manifest = Join-Path $ConfigDir ".service-install-$Name"
$Account = "NT SERVICE\$Name"
$Utf8 = New-Object System.Text.UTF8Encoding($false)   # no byte-order mark, and no ANSI re-encoding of existing bytes

function Say([string]$Text) { Write-Host "==> $Text" }
function Die([string]$Text) { throw "install-service: $Text" }

# ---- arguments: refusing is the escaping (paths end up in TOML, in a service command line and in icacls)
function Test-SafePath([string]$Label, [string]$Value, [bool]$Absolute = $true) {
  if (-not $Value) { return }
  if ($Value -notmatch '^[A-Za-z0-9._:\\/@+=,() -]+$' -or $Value -match '["''`$%&;|<>^]') { Die "${Label}: '$Value' has a character this installer does not accept" }
  if ($Value -match '(^|[\\/])\.\.([\\/]|$)') { Die "${Label}: '$Value' has a '..' component" }
  if ($Absolute -and -not [IO.Path]::IsPathRooted($Value)) { Die "${Label}: '$Value' must be an absolute path" }
}
foreach ($pair in @(@('-ConfigDir', $ConfigDir), @('-DataDir', $DataDir), @('-LogDir', $LogDir), @('-BinDir', $BinDir), @('-TlsCert', $TlsCert), @('-TlsKey', $TlsKey))) { Test-SafePath $pair[0] $pair[1] }
Test-SafePath '-Binary' $Binary
if ($Listen -notmatch '^[A-Za-z0-9._:\[\]-]+:\d+$') { Die "-Listen: '$Listen' is not host:port" }
if ($PublicUrl -and $PublicUrl -notmatch '^https://[A-Za-z0-9._:\[\]/@%+=,-]+$') { Die "-PublicUrl: '$PublicUrl' must be an https URL" }
if (($TlsCert -and -not $TlsKey) -or ($TlsKey -and -not $TlsCert)) { Die '-TlsCert and -TlsKey go together' }

function Test-Admin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-Native([string]$File, [string[]]$Arguments) {
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) { Die "$File $($Arguments -join ' ') exited $LASTEXITCODE" }
}
function Get-ServiceOrNull { Get-Service -Name $Name -ErrorAction SilentlyContinue }
function Write-Text([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $Utf8) }
function Read-Text([string]$Path) { if (Test-Path -LiteralPath $Path) { [IO.File]::ReadAllText($Path, $Utf8) } else { '' } }

# ---- ownership and reparse points: nothing a non-administrator controls is trusted
# SYSTEM, Administrators, TrustedInstaller
$TrustedOwnerSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Test-Reparse([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  return ($null -ne $item) -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}
function Assert-Trusted([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  # every existing component up to the root: a junction anywhere in the chain redirects what an admin tool then does
  $walk = [IO.Path]::GetFullPath($Path)
  while ($walk -and ($walk -ne [IO.Path]::GetPathRoot($walk))) {
    if (Test-Reparse $walk) { Die "$walk is a junction or other reparse point: refusing" }
    $walk = Split-Path -Parent $walk
  }
  # Compared as SIDs, never as names: the names are localized ("Administratoren", "SYSTEM") and a lookalike account can carry one.
  $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin $TrustedOwnerSids) {
    Die "$Path is owned by $owner, not by SYSTEM (S-1-5-18) or the Administrators (S-1-5-32-544): it may have been planted before this install; remove it or take ownership yourself, then run this again"
  }
}
$Created = New-Object System.Collections.Generic.List[string]   # files and directories this run created: what a rollback removes

# A directory this script creates is protected BEFORE anything is put into it.
# The SID of NT SERVICE\<name>: SHA-1 of the upper-cased name in UTF-16LE as five little-endian words under S-1-5-80.
function Get-ServiceSid([string]$ServiceName) {
  $sha = [Security.Cryptography.SHA1]::Create()
  $hash = $sha.ComputeHash([Text.Encoding]::Unicode.GetBytes($ServiceName.ToUpperInvariant()))
  'S-1-5-80-' + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($hash, 4 * $_) }) -join '-')
}
# True when every entry that GRANTS access names SYSTEM, the Administrators, CREATOR OWNER or the service's own account.
function Test-DaclPrivate([string]$Path) {
  $allowed = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', (Get-ServiceSid $Name))
  # The directory AND everything under it: a file inside that a user can read or replace makes the directory not private. A link
  # anywhere below is refused outright.
  $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    if ((Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $TrustedOwnerSids) { return $false }
    foreach ($rule in (Get-Acl -LiteralPath $item.FullName).Access) {
      if ($rule.AccessControlType -ne 'Allow') { continue }
      $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if ($sid -notin $allowed) { return $false }
    }
  }
  return $true
}

function New-ProtectedDirectory([string]$Path) {
  if (Test-Path -LiteralPath $Path) {
    Assert-Trusted $Path
    $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
    if ($children.Count -eq 0) {
      # An empty directory is ours to take over completely: its DACL is replaced, not trusted.
      Invoke-Native icacls @($Path, '/setowner', '*S-1-5-32-544')
      Invoke-Native icacls @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    } elseif (-not (Test-DaclPrivate $Path)) {
      Die "$Path already holds files and its ACL grants access beyond SYSTEM, Administrators and the service account: it is not this installer's. Move it away or fix its ACL, then run this again"
    }
    return
  }
  $parent = Split-Path -Parent $Path
  if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-ProtectedDirectory $parent }
  Assert-Trusted $parent
  New-Item -ItemType Directory -Path $Path | Out-Null
  $Created.Add($Path)
  Invoke-Native icacls @($Path, '/setowner', '*S-1-5-32-544')
  Invoke-Native icacls @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
  Assert-Trusted $Path
}

function Add-Record([string]$Line) { [IO.File]::AppendAllText($Manifest, "$Line`r`n", $Utf8) }
function Test-Recorded([string]$Line) { (Test-Path -LiteralPath $Manifest) -and ((Read-Text $Manifest) -split "`r?`n" -contains $Line) }

# The service account exists only once the service does, so its ACEs are added after the service is registered.
function Set-ServiceAcls {
  Invoke-Native icacls @($ConfigDir, '/grant:r', "${Account}:(OI)(CI)RX")
  foreach ($dir in @($DataDir, $LogDir)) { Invoke-Native icacls @($dir, '/grant:r', "${Account}:(OI)(CI)M") }
  # a key or certificate outside the config directory is read by the service: it must be readable by it, and by nobody else
  foreach ($file in @($TlsCert, $TlsKey)) {
    if ($file) {
      Assert-Trusted $file
      Invoke-Native icacls @($file, '/grant:r', "${Account}:R")
    }
  }
  Invoke-Native icacls @($BinDir, '/grant:r', "${Account}:(OI)(CI)RX")
}

# Run with the machine's own PATH, not the shell's: the service manager starts the service with no PATH of ours, so a library
# found only through a shim directory on the build machine would be found here and missing there.
function Test-Config([string]$Exe) {
  $saved = $env:PATH
  try {
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
    $env:PROBATION_SERVICE_NAME = $Name   # the key-file check accepts THIS service's virtual account, whatever the service is called
    & $Exe check-config $ConfigFile
    if ($LASTEXITCODE -ne 0) { Die "$Exe rejects $ConfigFile" }
  } finally { $env:PATH = $saved; Remove-Item Env:\PROBATION_SERVICE_NAME -ErrorAction SilentlyContinue }
}

function New-ConfigIfAbsent {
  if (Test-Path -LiteralPath $ConfigFile) { Assert-Trusted $ConfigFile; Say "Keeping the existing $ConfigFile"; return }
  $sample = Join-Path $Res 'config.sample.toml'
  if (-not (Test-Path -LiteralPath $sample)) { Die "missing $sample" }
  $url = if ($PublicUrl) { $PublicUrl } else { 'https://localhost:' + ($Listen -replace '^.*:', '') }
  # TOML literal strings (single quotes) take a Windows path without escaping; the alphabet check above keeps quotes out.
  $text = [IO.File]::ReadAllText($sample, $Utf8)
  # [regex]::Replace with a fixed replacement text works in Windows PowerShell 5.1 as well (no `$` in a value is ever special).
  $set = { param($t, $key, $line) [regex]::Replace($t, "(?m)^$key = .*$", [Text.RegularExpressions.MatchEvaluator]{ param($m) $line }) }
  $text = & $set $text 'listen' "listen = `"$Listen`""
  $text = & $set $text 'public_url' "public_url = `"$url`""
  $text = & $set $text 'data_dir' "data_dir = '$DataDir'"
  $text = & $set $text 'blocklist_file' "blocklist_file = '$Blocklist'"
  # The decision log file rolls itself over; the operational log is the service's own bounded file in the same directory.
  $text += "`nlog_file_path = '$(Join-Path $LogDir 'decisions.ndjson')'`nlog_file_max_bytes = 104857600`n"
  if ($TlsCert) { $text += "tls_cert_path = '$TlsCert'`ntls_key_path = '$TlsKey'`n" }
  Write-Text $ConfigFile $text
  $Created.Add($ConfigFile)
  Add-Record "file:$ConfigFile"
  Say "Created $ConfigFile (listen $Listen, public_url $url)"
}

# The libraries the release ships beside probation.exe (libcrypto, for the OCSP code) go next to it in BinDir, verified against the
# package's SHA256SUMS, so the service finds them without anything on a machine-wide PATH.
function Get-PackageFiles { @($Binary) + @(Get-ChildItem -LiteralPath (Split-Path -Parent $Binary) -Filter '*.dll' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
function Assert-PackageHashes {
  $dir = Split-Path -Parent $Binary
  # The same file however it is spelled (forward slashes, `..`, a relative path): compared canonically.
  $shipped = (Test-Path -LiteralPath $Binary) -and ([IO.Path]::GetFullPath($Binary) -ieq [IO.Path]::GetFullPath((Join-Path $Here 'probation.exe')))
  $release = Test-Path -LiteralPath (Join-Path $Here 'RELEASE-PACKAGE')
  $dlls = @(Get-PackageFiles | Where-Object { $_ -ne $Binary })
  # The release links OpenSSL into probation.exe: it ships NO library. A package that carries one is not this release, and a DLL beside a
  # service executable is a planting vector, so it is refused rather than installed.
  if ($dlls.Count -gt 0) { Die "the package holds a library ($(Split-Path -Leaf $dlls[0])); the release ships none (OpenSSL is linked in): refusing" }
  if ($NoVerify) {
    Write-Warning "verification of $Binary is DISABLED (-NoVerify): its hashes, attestation and signature are NOT checked"
    return
  }
  # Verified BEFORE any file is copied. No SHA256SUMS is itself a refusal: a package that cannot say what it holds is not verified.
  $sums = Join-Path $dir 'SHA256SUMS'
  if (-not (Test-Path -LiteralPath $sums)) { Die "$dir has no SHA256SUMS, so the files cannot be verified: use a release package, or pass -NoVerify for a build you made yourself" }
  $want = @{}
  foreach ($line in (Read-Text $sums) -split "`r?`n") { if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $want[$Matches[2].Trim()] = $Matches[1].ToLower() } }
  foreach ($file in Get-PackageFiles) {
    $leaf = Split-Path -Leaf $file
    if (-not $want.ContainsKey($leaf)) { Die "$leaf is not listed in SHA256SUMS" }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower() -ne $want[$leaf]) { Die "$leaf does not match SHA256SUMS" }
  }
  if (-not $shipped) { return }
  if (-not $release) {
    if (-not $DevPackage) { Die "$Here has no RELEASE-PACKAGE marker, so it is not a release package and its provenance cannot be verified: pass -DevPackage to install a build you made yourself anyway (or -Binary for an arbitrary binary)" }
    Write-Warning "$Binary comes from a package that is not marked as a release (-DevPackage): it is installed without a provenance guarantee"
  }
  # Provenance, pinned to this repository and its release workflow. In a release package a missing gh, cosign or bundle REFUSES.
  $repo = if ($env:PROBATION_RELEASE_REPO) { $env:PROBATION_RELEASE_REPO } else { 'postfix/probation' }
  if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    if ($release) { Die 'this is a release package and gh is not installed, so its attestation cannot be verified: install gh, or pass -NoVerify to accept it unchecked' }
    Say "gh is not installed: the release attestation of $Binary was NOT verified"
  } else {
    & gh attestation verify $Binary --repo $repo --signer-workflow "$repo/.github/workflows/release.yml" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "the release attestation of probation.exe does not verify (gh attestation verify, pinned to $repo and its release workflow); use -NoVerify only for a build you made yourself" }
    Say 'Verified the release attestation of probation.exe'
  }
  $bundle = if ($CosignBundle) { $CosignBundle } elseif (Test-Path -LiteralPath "$Binary.sigstore.json") { "$Binary.sigstore.json" } else { Join-Path $Here 'probation.sigstore.json' }
  if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
    if ($release) { Die 'this is a release package and cosign is not installed: install cosign, or pass -NoVerify' }
    Say "cosign is not installed: the cosign signature of $Binary was NOT verified"
  } elseif (-not (Test-Path -LiteralPath $bundle)) {
    if ($release) { Die "this is a release package and its cosign bundle is missing ($bundle): download probation-<version>-<target>.sigstore.json, or pass -NoVerify" }
    Say "no cosign bundle ($bundle): the cosign signature of $Binary was NOT verified"
  } else {
    & cosign verify-blob --bundle $bundle --certificate-identity-regexp ("^https://github\.com/" + [regex]::Escape($repo).Replace("\/", "/") + "/\.github/workflows/release\.yml@refs/tags/.+$") --certificate-oidc-issuer https://token.actions.githubusercontent.com $Binary 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "the cosign signature of $Binary does not verify; use -NoVerify only for a build you made yourself" }
    Say 'Verified the cosign signature of probation.exe'
  }
}

function Install-BinaryFiles {
  if (-not $Binary -or -not (Test-Path -LiteralPath $Binary)) { Die "no probation binary at '$Binary' (-Binary)" }
  if (-not $script:Verified) { Assert-PackageHashes; $script:Verified = $true }
  New-ProtectedDirectory $BinDir
  foreach ($file in Get-PackageFiles) {
    $target = Join-Path $BinDir (Split-Path -Leaf $file)
    if ($Action -eq 'install' -and (Test-Path -LiteralPath $target) -and -not (Test-Recorded "file:$target") `
        -and ((Get-FileHash -LiteralPath $file).Hash -ne (Get-FileHash -LiteralPath $target).Hash)) {
      Die "$target exists and was not installed by this script; use 'upgrade', or -BinDir/-Name for a second install"
    }
    $existed = Test-Path -LiteralPath $target
    # Beside the target, then renamed over it: a crash leaves one whole file.
    Copy-Item -LiteralPath $file -Destination "$target.new" -Force
    Move-Item -LiteralPath "$target.new" -Destination $target -Force
    if (-not $existed) { $Created.Add($target); Add-Record "file:$target" }
  }
}

# The documented way to set the pre-shutdown allowance: ChangeServiceConfig2(SERVICE_CONFIG_PRESHUTDOWN_INFO).
function Set-PreshutdownTimeout([int]$Milliseconds) {
  if (-not ('ProbationScm' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class ProbationScm {
  [StructLayout(LayoutKind.Sequential)] public struct PreshutdownInfo { public uint Timeout; }
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenServiceW(IntPtr h, string n, uint a);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool ChangeServiceConfig2W(IntPtr s, uint level, ref PreshutdownInfo info);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
  public static void Set(string name, uint ms) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001);
    if (scm == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    IntPtr svc = OpenServiceW(scm, name, 0x0002);
    if (svc == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    PreshutdownInfo info = new PreshutdownInfo(); info.Timeout = ms;
    bool ok = ChangeServiceConfig2W(svc, 7, ref info);   // SERVICE_CONFIG_PRESHUTDOWN_INFO
    int err = Marshal.GetLastWin32Error();
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    if (!ok) throw new System.ComponentModel.Win32Exception(err);
  }
}
'@
  }
  [ProbationScm]::Set($Name, [uint32]$Milliseconds)
}

# The service definition: re-applied by install and by upgrade. A failure (exit 75 after a settings push, a crash, a fatal error,
# a process that dies before reporting Running) ends the process WITHOUT `Stopped`, which the service control manager treats as a
# failure: it restarts after 5 s, 5 s, then 60 s (reset after a day). An operator's stop is reported Stopped and is not restarted
# (failureflag 0). Microsoft does not document recovery for a process that dies in START_PENDING; it is expected to take the
# same path and that is verified only on a runner (evidence lanes).
function Set-ServiceDefinition {
  Invoke-Native sc.exe @('sidtype', $Name, 'unrestricted')
  Invoke-Native sc.exe @('description', $Name, 'Filtering proxy for package registries (probation).')
  Invoke-Native sc.exe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/60000')
  Invoke-Native sc.exe @('failureflag', $Name, '0')
  # The service's own environment names the service, for the key-file ACL check (the documented per-service Environment value).
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Environment -PropertyType MultiString -Value @("PROBATION_SERVICE_NAME=$Name") -Force | Out-Null
  Set-PreshutdownTimeout 45000   # the 45 s stop allowance (the firewall drains requests for 30 s first)
}

# Registered Disabled and as the virtual account from the start: never a LocalSystem service, never one that starts before the
# ACLs are in place. Automatic only when everything has been verified.
function Register-Service {
  $command = "`"$BinPath`" service --config `"$ConfigFile`" --log-dir `"$LogDir`""
  New-Service -Name $Name -BinaryPathName $command -DisplayName 'Probation package firewall' -StartupType Disabled | Out-Null
  Add-Record "service:$Name"
  Invoke-Native sc.exe @('config', $Name, 'obj=', $Account)
  Set-ServiceDefinition
}

function Start-AndWait {
  Start-Service -Name $Name
  (Get-Service -Name $Name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
# Up, and still up after a few seconds: a binary that validates its configuration and dies at bind is a failed start.
function Wait-Stays-Up {
  Start-AndWait
  for ($n = 0; $n -lt 5; $n++) { Start-Sleep -Seconds 1; if ((Get-Service -Name $Name).Status -ne 'Running') { Die "$Name stopped again within five seconds of starting" } }
}
function Stop-AndWait {
  $service = Get-ServiceOrNull
  if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $Name -Force
    (Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
  }
}

# ---- package-manager settings: only index/registry lines; every other line, comment and credential stays byte for byte.
# The files sit where users can pre-create them, so a reparse point is refused and the rewrite goes through a temporary file.
function Save-Preserving([string]$Path, [string]$Text) {
  if ((Test-Reparse $Path) -or (Test-Reparse (Split-Path -Parent $Path))) { Die "$Path is, or sits behind, a link: refusing to write through it" }
  $tmp = "$Path.probation-new"
  Write-Text $tmp $Text
  Move-Item -LiteralPath $tmp -Destination $Path -Force
}
function Split-Lines([string]$Text) { if ($Text) { [regex]::Split($Text, '(?<=\n)') | Where-Object { $_ -ne '' } } else { @() } }
function Set-IniValue([string]$Path, [string]$Section, [string]$Key, [string]$Value) {
  $lines = @(Split-Lines (Read-Text $Path)); $start = -1; $end = $lines.Count
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*\[(.+?)\]\s*$') { if ($start -ge 0) { $end = $i; break }; if ($Matches[1] -eq $Section) { $start = $i } }
  }
  if ($start -lt 0) {
    if ($lines.Count -gt 0 -and -not $lines[-1].EndsWith("`n")) { $lines[-1] += "`r`n" }
    $lines += "[$Section]`r`n"; $start = $lines.Count - 1; $end = $lines.Count
  }
  for ($i = $start + 1; $i -lt $end; $i++) {
    if ($lines[$i] -match "^\s*$([regex]::Escape($Key))\s*[=:]") {
      $eol = if ($lines[$i].EndsWith("`r`n")) { "`r`n" } else { "`n" }
      $lines[$i] = "$Key = $Value$eol"; Save-Preserving $Path (-join $lines); return
    }
  }
  $lines = @($lines[0..$start]) + @("$Key = $Value`r`n") + @(if ($end -gt $start + 1) { $lines[($start + 1)..($end - 1)] }) + @(if ($end -lt $lines.Count) { $lines[$end..($lines.Count - 1)] })
  Save-Preserving $Path (-join $lines)
}
function Set-NpmValue([string]$Path, [string]$Key, [string]$Value) {
  $lines = @(Split-Lines (Read-Text $Path)); $found = $false
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^$([regex]::Escape($Key))=") { $eol = if ($lines[$i].EndsWith("`r`n")) { "`r`n" } else { "`n" }; $lines[$i] = "$Key=$Value$eol"; $found = $true }
  }
  if (-not $found) {
    if ($lines.Count -gt 0 -and -not $lines[-1].EndsWith("`n")) { $lines[-1] += "`r`n" }
    $lines += "$Key=$Value`r`n"
  }
  Save-Preserving $Path (-join $lines)
}
function Set-Tools {
  foreach ($toolFile in @($NpmRc, $PipIni)) { if ($toolFile -and ((Test-Reparse $toolFile) -or (Test-Reparse (Split-Path -Parent $toolFile)))) { Die "$toolFile is, or sits behind, a link: refusing to rewrite it" } }
  $scheme = if ($PublicUrl) { $PublicUrl.TrimEnd('/') } else { 'https://localhost:' + ($Listen -replace '^.*:', '') }
  $npm = Get-Command npm -ErrorAction SilentlyContinue
  if (-not $NpmRc -and $npm) { $NpmRc = (& $npm.Source config get globalconfig 2>$null) }
  if ($NpmRc -and $NpmRc -ne 'undefined') {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $NpmRc) | Out-Null
    Set-NpmValue $NpmRc 'registry' "$scheme/npm/"
    Set-NpmValue $NpmRc 'audit' 'false'
    Say "Updated $NpmRc (registry and audit only; credential entries untouched)"
  } else { Say 'No npm found: npm settings skipped' }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PipIni) | Out-Null
  Set-IniValue $PipIni 'global' 'index-url' "$scheme/pypi/simple/"
  Say "Updated $PipIni (index-url only)"
}

# ---- actions
if (-not (Test-Admin)) { Die 'run this from an elevated PowerShell' }

function Invoke-InstallRollback {
  Say 'The install failed: removing what this run created'
  if ((Get-ServiceOrNull) -and (Test-Recorded "service:$Name")) { try { Stop-AndWait } catch { }; & sc.exe delete $Name | Out-Null }
  for ($i = $Created.Count - 1; $i -ge 0; $i--) {
    $path = $Created[$i]
    if ((Test-Path -LiteralPath $path) -and -not (Test-Reparse $path)) { Remove-Item -LiteralPath $path -Force -Recurse -ErrorAction SilentlyContinue }
  }
}

switch ($Action) {
  'install' {
    if (Get-ServiceOrNull) {
      if (Test-Recorded "service:$Name") { Die "$Name is already installed here; use 'upgrade'" }
      Die "a service named $Name exists and was not installed by this script; use another -Name"
    }
    # Verified before ANY directory or file is created: a package that does not verify leaves nothing behind.
    Assert-PackageHashes
    $script:Verified = $true
    try {
      # the directories first, protected, before a single file is written
      foreach ($dir in @($ConfigDir, $DataDir, $LogDir)) { New-ProtectedDirectory $dir }
      New-ConfigIfAbsent
      if (-not (Test-Path -LiteralPath $Blocklist)) {
        Copy-Item -LiteralPath (Join-Path $Res 'blocklist.sample.json') -Destination $Blocklist
        $Created.Add($Blocklist); Add-Record "file:$Blocklist"
      } else { Assert-Trusted $Blocklist; Say "Keeping the existing $Blocklist" }
      Install-BinaryFiles
      Test-Config $BinPath
      Register-Service
      Set-ServiceAcls
      if ($ConfigureTools) { Set-Tools }
      Set-Service -Name $Name -StartupType Automatic
      Say "Installed service $Name ($Account)"
      if (-not $NoStart) { Wait-Stays-Up; Say "Started $Name" }
    } catch {
      Invoke-InstallRollback
      throw
    }
  }
  'upgrade' {
    if (-not (Get-ServiceOrNull) -or -not (Test-Recorded "service:$Name")) { Die "nothing to upgrade: $Name was not installed by this script (run 'install')" }
    Assert-Trusted $ConfigFile
    if (-not (Test-Path -LiteralPath $ConfigFile)) { Die "$ConfigFile is missing; an upgrade never creates one" }
    if (-not $Binary -or -not (Test-Path -LiteralPath $Binary)) { Die "no probation binary at '$Binary' (-Binary)" }
    Assert-PackageHashes   # verified before anything is touched
    $script:Verified = $true
    Test-Config $Binary   # the new binary must accept the existing configuration before anything is replaced
    Stop-AndWait
    $files = @(Get-ChildItem -LiteralPath $BinDir -File | Where-Object { $_.Name -eq 'probation.exe' -or $_.Extension -eq '.dll' } | ForEach-Object { $_.FullName })
    foreach ($f in $files) { Copy-Item -LiteralPath $f -Destination "$f.prev" -Force }
    try {
      Install-BinaryFiles
      Test-Config $BinPath
      Set-ServiceDefinition   # the definition is part of the upgrade
      if ($ConfigureTools) { Set-Tools }
      if (-not $NoStart) { Wait-Stays-Up }
    } catch {
      Say 'The upgrade failed: restoring the previous files'
      try { Stop-AndWait } catch { }
      foreach ($f in $files) { if (Test-Path -LiteralPath "$f.prev") { Copy-Item -LiteralPath "$f.prev" -Destination $f -Force } }
      if (-not $NoStart) { try { Start-AndWait } catch { Write-Warning 'the previous service did not start either' } }
      throw
    }
    Say "Upgraded $BinPath (previous kept as .prev); configuration, blocklist and data untouched"
  }
  'uninstall' {
    if (-not (Test-Path -LiteralPath $Manifest)) { Die "no install record at $Manifest" }
    Assert-Trusted $ConfigDir
    Stop-AndWait
    if (Get-ServiceOrNull) { Invoke-Native sc.exe @('delete', $Name) }
    # Only paths this script computes itself can ever be removed, and only if the record names them.
    $dlls = @(Get-ChildItem -LiteralPath $BinDir -Filter '*.dll' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $ours = @($BinPath) + $dlls
    $refused = $false
    foreach ($line in (Read-Text $Manifest) -split "`r?`n") {
      if ($line -notlike 'file:*') { continue }
      $path = [IO.Path]::GetFullPath($line.Substring(5))
      if ($path -eq [IO.Path]::GetFullPath($ConfigFile) -or $path -eq [IO.Path]::GetFullPath($Blocklist)) { Say "Keeping $path"; continue }
      $match = $ours | Where-Object { [IO.Path]::GetFullPath($_) -ieq $path }
      if (-not $match) { Write-Warning "the install record names $path, which this installer never creates: refusing it"; $refused = $true; continue }
      if ((Test-Reparse $path) -or (Test-Reparse (Split-Path -Parent $path))) { Write-Warning "$path is behind a reparse point: refusing it"; $refused = $true; continue }
      Remove-Item -LiteralPath $path, "$path.prev" -Force -ErrorAction SilentlyContinue
      Say "Removed $path"
    }
    Remove-Item -LiteralPath $Manifest -Force
    Say "Left in place: $ConfigDir, $DataDir and $LogDir. Delete them yourself if you mean to."
    if ($refused) { Die 'the install record named paths that were refused' }
  }
}
