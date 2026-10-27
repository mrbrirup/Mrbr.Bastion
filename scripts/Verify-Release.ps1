#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ResultsDirectory = (Join-Path $PSScriptRoot '../artifacts/verification'),
    [switch]$IncludeTls
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The release verification includes WinForms and requires Windows.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$results = [IO.Path]::GetFullPath($ResultsDirectory)
$null = New-Item -ItemType Directory -Path $results -Force
function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed (exit $LASTEXITCODE): $($Arguments[0])" }
}
Push-Location $root
$previousTls = $env:BASTION_RUN_TLS_TESTS
try {
    $requiredSdk = (Get-Content global.json -Raw | ConvertFrom-Json).sdk.version
    $actualSdk = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualSdk -ne $requiredSdk) { throw "Install SDK $requiredSdk; selected SDK was $actualSdk." }
    Invoke-Dotnet -Arguments @('restore','Mrbr.Bastion.slnx','--locked-mode','--verbosity','minimal')
    Invoke-Dotnet -Arguments @('build','Mrbr.Bastion.slnx','-c','Release','--no-restore','--verbosity','minimal')
    # A hosted Windows runner can be elevated. Never start live kernel tracing implicitly.
    $env:BASTION_RUN_TLS_TESTS = if ($IncludeTls) { '1' } else { $null }
    Invoke-Dotnet -Arguments @('test','tests/Mrbr.Bastion.Tests/Mrbr.Bastion.Tests.csproj','-c','Release','--no-build','--no-restore',
        '--filter','FullyQualifiedName!~RecoveryAndEtwTests.LiveEtw','--logger','trx;LogFileName=core.trx','--results-directory',$results)
    Invoke-Dotnet -Arguments @('test','tests/Mrbr.Bastion.Desktop.Tests/Mrbr.Bastion.Desktop.Tests.csproj','-c','Release','--no-build','--no-restore',
        '--logger','trx;LogFileName=desktop.trx','--results-directory',$results)
    $auditLines = & dotnet package list --project Mrbr.Bastion.slnx --vulnerable --include-transitive --no-restore --format json --output-version 1
    if ($LASTEXITCODE -ne 0) { throw 'NuGet vulnerability audit failed.' }
    $auditText = $auditLines -join [Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $results 'dependency-audit.json'),$auditText)
    $audit = $auditText | ConvertFrom-Json
    if ($audit.problems) { throw 'NuGet reported problems while auditing dependencies.' }
    foreach ($project in $audit.projects) {
        foreach ($framework in $project.frameworks) {
            foreach ($package in @($framework.topLevelPackages) + @($framework.transitivePackages)) {
                if ($package.vulnerabilities) { throw "Known vulnerability reported for dependency $($package.id)." }
            }
        }
    }
    Write-Host "Release verification passed with SDK $actualSdk. Results: $results"
}
finally { $env:BASTION_RUN_TLS_TESTS = $previousTls; Pop-Location }
