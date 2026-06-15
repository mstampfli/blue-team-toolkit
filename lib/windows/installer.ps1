$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$Manifest = Join-Path $Script:ToolkitDir 'tools.json'
if (-not (Test-Path $Manifest)) { Write-Host "tools.json not found at $Manifest" -ForegroundColor Red; Pause-Toolkit; return }

$tools = (Get-Content $Manifest -Raw | ConvertFrom-Json).tools | Where-Object { $_.windows }

# Top-level mode: ALL (default) / CUSTOM / QUIT
Write-Host "Install mode:" -ForegroundColor Cyan
Write-Host "  1) ALL     -- install every Windows tool from manifest (recommended on first run)"
Write-Host "  2) CUSTOM  -- pick from list (* = high priority)"
Write-Host "  3) QUIT"
$mode = Read-Host "Pick [1]"
if ([string]::IsNullOrWhiteSpace($mode)) { $mode = '1' }

$selected = $null
switch ($mode) {
    '1' {
        $selected = $tools | Select-Object id, name, description
    }
    '2' {
        $picks = $tools | Select-Object id, name, description, @{n='Star';e={ if ($_.star) { 'YES' } else { '' } }}
        try {
            $selected = $picks | Out-GridView -Title "Pick tools (Ctrl+click multi-select; Star=YES = high priority)" -PassThru
        } catch {
            Write-Host "Out-GridView unavailable, falling back to console picker." -ForegroundColor Yellow
            for ($i=0; $i -lt $picks.Count; $i++) {
                $row = $picks[$i]
                $marker = if ($row.Star -eq 'YES') { '*' } else { ' ' }
                "{0,3}) {1} {2,-22} - {3}" -f $i, $marker, $row.id, $row.description | Out-Host
            }
            $idxs = (Read-Host "Comma-separated indices (e.g. 0,3,7)").Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            $selected = $idxs | ForEach-Object { $picks[[int]$_] }
        }
    }
    default { return }
}
if (-not $selected) { return }
Write-Host ""
Write-Host "[installer] installing $($selected.Count) tool(s)..." -ForegroundColor Cyan

function Install-WingetPkg {
    param($id, $pkg)
    Write-Log "INSTALL winget: $pkg"
    & winget install --silent --accept-source-agreements --accept-package-agreements --id $pkg
}
function Install-PipPkg {
    param($id, $pkg)
    Write-Log "INSTALL pipx: $pkg"
    $hasPipx = $null -ne (Get-Command pipx -ErrorAction SilentlyContinue)
    if ($hasPipx) { & pipx install $pkg }
    else          { & pip install --user $pkg }
}
function Install-Url {
    param($id, $url, $filename)
    if (-not $filename) { $filename = [IO.Path]::GetFileName($url) }
    $out = Join-Path $Script:ToolsDir $filename
    Write-Log "DOWNLOAD url: $url -> $out"
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}
function Install-Git {
    param($id, $repo)
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "git not installed; skipping $id" -ForegroundColor Yellow; return
    }
    $dir = Join-Path $Script:ToolsDir $id
    if (Test-Path "$dir\.git") { & git -C $dir pull --ff-only }
    else                       { & git clone --depth 1 $repo $dir }
}
function Install-GitHubRelease {
    param($id, $repo, $pattern)
    $api = "https://api.github.com/repos/$repo/releases/latest"
    Write-Log "FETCH gh release: $repo (pattern: $pattern)"
    $rel = Invoke-RestMethod -Uri $api -UseBasicParsing -Headers @{ 'User-Agent' = 'blueteam-toolkit' }
    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { Write-Host "ERROR: no asset matching $pattern in $repo" -ForegroundColor Red; Write-Log "ERROR no asset $pattern in $repo"; return }
    Install-Url $id $asset.browser_download_url $asset.name
}

$count = 0; $total = $selected.Count
foreach ($t in $selected) {
    $count++
    $entry = $tools | Where-Object { $_.id -eq $t.id }
    $w = $entry.windows
    Write-Host ("[{0}/{1}] {2}" -f $count, $total, $t.id) -ForegroundColor Cyan
    try {
        switch ($w.method) {
            'winget'         { Install-WingetPkg $t.id $w.package | Out-Null }
            'pip'            { Install-PipPkg    $t.id $w.package | Out-Null }
            'pipx'           { Install-PipPkg    $t.id $w.package | Out-Null }
            'url'            { Install-Url       $t.id $w.url $w.filename }
            'git_clone'      { Install-Git       $t.id $w.repo }
            'github_release' { Install-GitHubRelease $t.id $w.repo $w.pattern }
            'manual'         { Write-Host "       MANUAL: $($w.note)" -ForegroundColor Yellow; Write-Log "MANUAL: $($t.id) - $($w.note)" }
            default          { Write-Host "       Unknown method: $($w.method)" -ForegroundColor Red }
        }
        Write-Log "OK: $($t.id)"
        Write-Host "       OK"
    } catch {
        Write-Log "FAIL: $($t.id) -- $_"
        Write-Host "       FAIL: $_" -ForegroundColor Red
    }
}

Write-Host "`nDone. Downloads in: $Script:ToolsDir" -ForegroundColor Green
Pause-Toolkit
