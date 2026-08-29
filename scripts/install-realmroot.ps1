#!/usr/bin/env pwsh

param(
    [string]$Version = $Env:REALMROOT_VERSION
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ([string]::IsNullOrWhiteSpace($Version) -or $Version -eq 'stable') {
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/realmroot/cli/releases/latest'
    $Version = $release.tag_name.TrimStart('v')
} else {
    $Version = $Version.TrimStart('v')
}
if ($Version -notmatch '^[0-9A-Za-z.+-]+$') {
    throw "Invalid Realmroot version: $Version"
}

$architecture = $Env:PROCESSOR_ARCHITEW6432
if ([string]::IsNullOrWhiteSpace($architecture)) {
    $architecture = $Env:PROCESSOR_ARCHITECTURE
}
switch ($architecture) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "Unsupported Windows architecture: $architecture" }
}

$filename = "realmroot_${Version}_windows_${arch}.zip"
$releaseUrl = "https://github.com/realmroot/cli/releases/download/v${Version}"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("realmroot-install-" + [guid]::NewGuid())
$archivePath = Join-Path $tempDir $filename
$checksumsPath = Join-Path $tempDir 'checksums.txt'
New-Item $tempDir -ItemType Directory | Out-Null

try {
    Invoke-WebRequest -Uri "$releaseUrl/$filename" -OutFile $archivePath
    Invoke-WebRequest -Uri "$releaseUrl/checksums.txt" -OutFile $checksumsPath

    $escapedFilename = [regex]::Escape($filename)
    $checksumPattern = "^(?<hash>[0-9a-fA-F]{64})\s+\*?${escapedFilename}$"
    $checksumMatches = @(
        Get-Content -Path $checksumsPath | ForEach-Object {
            if ($_ -match $checksumPattern) {
                $Matches['hash'].ToLowerInvariant()
            }
        }
    )
    if ($checksumMatches.Count -ne 1) {
        throw "Expected one SHA-256 checksum for $filename"
    }

    $actualChecksum = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualChecksum -ne $checksumMatches[0]) {
        throw "Checksum mismatch for $filename"
    }

    Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force

    $versionDir = Join-Path $Env:USERPROFILE ".local\opt\realmroot-v$Version"
    $sourceBin = Join-Path $versionDir 'bin'
    $destinationBin = Join-Path $Env:USERPROFILE '.local\bin'
    $sourceCommand = Join-Path $sourceBin 'realmroot.exe'
    $destinationCommand = Join-Path $destinationBin 'realmroot.exe'

    New-Item $sourceBin -ItemType Directory -Force | Out-Null
    New-Item $destinationBin -ItemType Directory -Force | Out-Null
    Move-Item -Path (Join-Path $tempDir 'realmroot.exe') -Destination $sourceCommand -Force
    Copy-Item -Path $sourceCommand -Destination $destinationCommand -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($pathEntries -notcontains $destinationBin) {
        [Environment]::SetEnvironmentVariable('Path', (($destinationBin) + ';' + $userPath).TrimEnd(';'), 'User')
    }

    Write-Output "Installed Realmroot v$Version at $destinationCommand"
    Write-Output 'Open a new PowerShell session before running realmroot.'
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Ignore
}
