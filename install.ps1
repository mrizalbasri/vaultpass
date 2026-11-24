$ErrorActionPreference = "Stop"

$Repo = "mrizalbasri/vaultpass"
$ApiUrl = "https://api.github.com/repos/$Repo/releases?per_page=1"

Write-Host "==> Mencari rilis terbaru VaultPass dari GitHub ($Repo)..." -ForegroundColor Cyan
$Releases = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "VaultPass-Installer" }
if (-not $Releases -or $Releases.Count -eq 0) {
    throw "Belum ada rilis VaultPass yang dipublikasikan di https://github.com/$Repo/releases"
}

$Release = $Releases[0]
$SetupAsset = $Release.assets | Where-Object { $_.name -like "*-setup.exe" } | Select-Object -First 1
$SumsAsset = $Release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1

if (-not $SetupAsset) {
    throw "Asset installer (*-setup.exe) tidak ditemukan pada rilis $($Release.tag_name)."
}
if (-not $SumsAsset) {
    throw "File verifikasi SHA256SUMS.txt tidak ditemukan pada rilis $($Release.tag_name)."
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vaultpass-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

try {
    $InstallerPath = Join-Path $TempDir $SetupAsset.name
    Write-Host "==> Mengunduh $($SetupAsset.name) ($($Release.tag_name))..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $SetupAsset.browser_download_url -OutFile $InstallerPath

    $SumsPath = Join-Path $TempDir "SHA256SUMS.txt"
    Invoke-WebRequest -Uri $SumsAsset.browser_download_url -OutFile $SumsPath

    $ExpectedHash = $null
    foreach ($line in Get-Content $SumsPath) {
        $parts = $line.Trim() -split "\s+", 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $SetupAsset.name) {
            $ExpectedHash = $parts[0].Trim().ToLowerInvariant()
            break
        }
    }
    if (-not $ExpectedHash) {
        throw "Entri checksum untuk $($SetupAsset.name) tidak ditemukan di SHA256SUMS.txt."
    }

    $ActualHash = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "Verifikasi SHA-256 GAGAL! Expected: $ExpectedHash, Actual: $ActualHash"
    }
    Write-Host "==> Checksum SHA-256 terverifikasi ($ActualHash)." -ForegroundColor Green

    Write-Host "==> Memasang VaultPass & mendaftarkan vaultpass-cli ke PATH..." -ForegroundColor Cyan
    $Proc = Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -PassThru
    if ($Proc.ExitCode -ne 0) {
        throw "Installer keluar dengan kode error $($Proc.ExitCode)."
    }

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $env:Path = "$UserPath;$MachinePath"

    Write-Host ""
    Write-Host "VaultPass $($Release.tag_name) berhasil terpasang!" -ForegroundColor Green
    Write-Host "- Aplikasi desktop tersedia di Desktop & Start Menu."
    Write-Host "- CLI siap digunakan: jalankan 'vaultpass-cli status' atau 'vaultpass-cli --help'."
}
finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
