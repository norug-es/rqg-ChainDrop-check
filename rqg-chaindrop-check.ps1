param(
    [string]$Path = "."
)

$ErrorActionPreference = "SilentlyContinue"
Set-Location $Path

$SelfNames = @(
    "rqg-chaindrop-check.ps1",
    "rqg-chaindrop-check.sh",
    "rqg-chaindrop-check-v1.1.ps1",
    "rqg-chaindrop-check-v1.1.sh"
)

$ExcludedPathPatterns = @(
    '\\node_modules\\',
    '\\\.git\\',
    '\\\.rqg\\',
    '\\threat-intel\\feeds\\',
    '\\rules\\'
)

function Is-ExcludedFile([string]$FullName, [string]$Name) {
    if ($SelfNames -contains $Name) { return $true }
    foreach ($p in $ExcludedPathPatterns) {
        if ($FullName -match $p) { return $true }
    }
    return $false
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " RQG ChainDrop Quick Check v1.1 - PowerShell" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Repo: $(Get-Location)"
Write-Host ""

$critical = 0
$warning = 0

function Section($title) {
    Write-Host ""
    Write-Host "---- $title ----" -ForegroundColor Yellow
}

Section "TEST 1/4 - Suspicious files and persistence locations"

$files = Get-ChildItem -Recurse -Force -File |
    Where-Object {
        -not (Is-ExcludedFile $_.FullName $_.Name) -and (
            $_.Name -match '^(setup\.mjs|math_init\.js|Math_Symbol\.js|router_runtime\.js)$' -or
            $_.FullName -match '\\\.claude\\|\\\.vscode\\|\\\.github\\workflows\\'
        )
    }

if ($files) {
    $files | Select-Object FullName | Format-Table -AutoSize
    Write-Host "[WARN] Review the files above manually." -ForegroundColor Yellow
    $warning++
} else {
    Write-Host "[OK] No suspicious filenames or persistence locations found." -ForegroundColor Green
}

Section "TEST 2/4 - package.json lifecycle scripts"

$packageFiles = Get-ChildItem -Recurse -Force -File -Filter "package.json" |
    Where-Object { -not (Is-ExcludedFile $_.FullName $_.Name) }

if (-not $packageFiles) {
    Write-Host "[INFO] No package.json found in the repository tree." -ForegroundColor DarkGray
} else {
    foreach ($pf in $packageFiles) {
        try {
            $pkg = Get-Content $pf.FullName -Raw | ConvertFrom-Json
            $flagged = $false
            foreach ($name in @("preinstall","install","postinstall","prepare")) {
                if ($pkg.scripts -and $pkg.scripts.PSObject.Properties.Name -contains $name) {
                    Write-Host "[WARN] $($pf.FullName): $name = $($pkg.scripts.$name)" -ForegroundColor Yellow
                    $flagged = $true
                }
            }
            if ($flagged) { $warning++ }
        } catch {
            Write-Host "[WARN] Could not parse $($pf.FullName)" -ForegroundColor Yellow
            $warning++
        }
    }
}

Section "TEST 3/4 - Known affected package/version and setup indicators"

$patterns = @(
    '"preinstall"',
    'setup\.mjs',
    '"?keyv"?\s*[:@].*6\.0\.0',
    '"?flat-cache"?\s*[:@].*6\.1\.24',
    '"?file-entry-cache"?\s*[:@].*11\.1\.6',
    '"?cacheable-request"?\s*[:@].*13\.0\.20',
    '"?cacheable"?\s*[:@].*2\.5\.1',
    '"?@cacheable/memory"?\s*[:@].*2\.2\.1',
    '"?cache-manager"?\s*[:@].*7\.2\.10',
    '"?@cacheable/node-cache"?\s*[:@].*3\.1\.2',
    '"?@cacheable/utils"?\s*[:@].*2\.5\.1',
    '"?@cacheable/net"?\s*[:@].*2\.1\.1',
    '"?ecto"?\s*[:@].*5\.0\.1'
)

$packageArtifacts = Get-ChildItem -Recurse -Force -File |
    Where-Object {
        $_.Name -in @("package.json","package-lock.json","npm-shrinkwrap.json","pnpm-lock.yaml","yarn.lock") -and
        -not (Is-ExcludedFile $_.FullName $_.Name)
    }

$matches = @()
foreach ($f in $packageArtifacts) {
    foreach ($p in $patterns) {
        $matches += Select-String -Path $f.FullName -Pattern $p
    }
}

if ($matches) {
    $matches | Select-Object Path, LineNumber, Line | Format-Table -Wrap
    Write-Host "[CRITICAL] ChainDrop-relevant package/version or setup indicator found." -ForegroundColor Red
    $critical++
} else {
    Write-Host "[OK] No known affected package/version or setup indicator found." -ForegroundColor Green
}

Section "TEST 4/4 - ChainDrop IoCs and behavioral markers"

$iocPatterns = @(
    'awqhnjewqjkl\.icu',
    'npm-cache\.com',
    'pypi-get\.com',
    'js-mirror\.com',
    'thebeautifulmarchoftime',
    'thebeautifulsnadsoftime',
    'IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients',
    '0xE1f2395ee43e45A1556EC6438a88c31B83493103',
    '0x53ed5143',
    'toJSON\s*\(\s*secrets\s*\)',
    '"?runOn"?\s*:\s*"?folderOpen"?',
    'SessionStart',
    '_NODE_RUNTIME_INIT=1',
    'tmp\.dpkg_14527\.lock',
    'gh-token-monitor'
)

$iocMatches = @()
Get-ChildItem -Recurse -Force -File |
    Where-Object {
        $_.Length -lt 5MB -and
        -not (Is-ExcludedFile $_.FullName $_.Name)
    } |
    ForEach-Object {
        foreach ($p in $iocPatterns) {
            $m = Select-String -Path $_.FullName -Pattern $p
            if ($m) { $iocMatches += $m }
        }
    }

if ($iocMatches) {
    $iocMatches | Select-Object Path, LineNumber, Line | Format-Table -Wrap
    Write-Host "[CRITICAL] One or more ChainDrop IoCs/behavioral markers were found." -ForegroundColor Red
    $critical++
} else {
    Write-Host "[OK] No known ChainDrop IoCs found." -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

if ($critical -gt 0) {
    Write-Host "RESULT: QUARANTINE / INVESTIGATE" -ForegroundColor Red
    Write-Host "Critical groups: $critical | Warning groups: $warning"
    exit 2
} elseif ($warning -gt 0) {
    Write-Host "RESULT: REVIEW" -ForegroundColor Yellow
    Write-Host "Critical groups: 0 | Warning groups: $warning"
    exit 1
} else {
    Write-Host "RESULT: NO KNOWN CHAINDROP INDICATORS FOUND" -ForegroundColor Green
    Write-Host "This is not a guarantee that the repository is safe."
    exit 0
}