#requires -Version 7.0
[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot '../artifacts/tools/gitleaks'))
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'This helper provisions the reviewed Windows x64 scanner. Use the official Gitleaks distribution on other platforms.'
}
$version = '8.30.1'
$expectedHash = 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'
$destinationPath = [IO.Path]::GetFullPath($Destination)
$null = New-Item -ItemType Directory -Path $destinationPath -Force
$archive = Join-Path $destinationPath "gitleaks_$($version)_windows_x64.zip"
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest "https://github.com/gitleaks/gitleaks/releases/download/v$version/gitleaks_$($version)_windows_x64.zip" -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    throw 'Gitleaks archive does not match the reviewed official release checksum.'
}
$tool = Join-Path $destinationPath "v$version"
if (-not (Test-Path -LiteralPath $tool)) { Expand-Archive -LiteralPath $archive -DestinationPath $tool }
Join-Path $tool 'gitleaks.exe'
