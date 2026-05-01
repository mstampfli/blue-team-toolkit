# Shared helpers for Windows scripts.

function Write-Log {
    param([string]$Message)
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Message
    Add-Content -Path $Script:LogFile -Value $line
}

function Pause-Toolkit { Read-Host "Press Enter to continue" | Out-Null }

function Confirm-YesNo {
    param([string]$Prompt, [string]$Default = 'N')
    $suffix = if ($Default -eq 'Y') { '[Y/n]' } else { '[y/N]' }
    $r = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
    return ($r -match '^[yY]')
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Invoke-Silent <Label> <LogFile> <FilePath> [ArgumentList]
# Runs an external process, redirecting stdout/stderr to LogFile.
# Prints a heartbeat every ~30s with elapsed/log size/growth/tail line.
function Invoke-Silent {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    Write-Host "[$Label] running -> $LogFile" -ForegroundColor Cyan
    Write-Host "[$Label] heartbeat every 30s — if size stops growing AND tail is unchanged across two beats, it's stuck"
    Write-Host ""
    Write-Log "Running $Label -> $LogFile"

    $t0 = Get-Date
    $errFile = "$LogFile.err"
    $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
        -RedirectStandardOutput $LogFile -RedirectStandardError $errFile `
        -NoNewWindow -PassThru

    $lastSize = 0
    $lastTail = ""
    while (-not $proc.HasExited) {
        for ($i = 0; $i -lt 6; $i++) {
            if ($proc.HasExited) { break }
            Start-Sleep -Seconds 5
        }
        if ($proc.HasExited) { break }
        $elapsed = [int]((Get-Date) - $t0).TotalSeconds
        $size    = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { 0 }
        $growth  = $size - $lastSize
        $tail    = if (Test-Path $LogFile) {
                      try { (Get-Content $LogFile -Tail 1 -ErrorAction SilentlyContinue) -replace '\x1b\[[\d;]*m','' }
                      catch { '' }
                   } else { '' }
        if ([string]::IsNullOrWhiteSpace($tail)) { $tail = '(no output yet)' }
        if ($tail.Length -gt 80) { $tail = $tail.Substring(0, 80) }
        $marker = if ($growth -eq 0 -and $tail -eq $lastTail) { '  [!] NO PROGRESS' } else { '' }
        Write-Host ("[{0}] alive: {1}s elapsed, log={2}B (+{3}B), tail: {4}{5}" -f $Label, $elapsed, $size, $growth, $tail, $marker)
        $lastSize = $size
        $lastTail = $tail
    }
    $dt = [int]((Get-Date) - $t0).TotalSeconds
    Write-Host ""
    Write-Host "[$Label] done in ${dt}s (exit=$($proc.ExitCode))" -ForegroundColor Green
    Write-Log "$Label done in ${dt}s exit=$($proc.ExitCode)"
}

# Record-Finding <Type> <Target> [Sha256] [ExtraHashtable]
# Appends one JSON-line record to $Script:OutputDir\findings.jsonl.
function Record-Finding {
    param(
        [Parameter(Mandatory)][string]$Type,
        [string]$Target = '',
        [string]$Sha256 = '',
        [hashtable]$Extra = @{}
    )
    $obj = [ordered]@{
        ts     = (Get-Date).ToUniversalTime().ToString('o')
        host   = $env:COMPUTERNAME
        type   = $Type
        target = $Target
        sha256 = if ($Sha256) { $Sha256 } else { $null }
    }
    foreach ($k in $Extra.Keys) { $obj[$k] = $Extra[$k] }
    $line = ($obj | ConvertTo-Json -Compress -Depth 6)
    Add-Content -Path (Join-Path $Script:OutputDir 'findings.jsonl') -Value $line
}

# Ensure-Extracted <ArchivePattern> <BinaryName>
# Auto-extracts a zip in $Script:ToolsDir if not already extracted.
# Returns full path to first matching .exe (or $null).
function Ensure-Extracted {
    param([string]$ArchivePattern, [string]$BinaryName)
    $archive = Get-ChildItem (Join-Path $Script:ToolsDir $ArchivePattern) -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $archive) { return $null }
    $extractDir = Join-Path $Script:ToolsDir "$BinaryName-extracted"
    $needsExtract = (-not (Test-Path $extractDir)) -or
                    @(Get-ChildItem $extractDir -ErrorAction SilentlyContinue).Count -eq 0
    if ($needsExtract) {
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        try { Expand-Archive -Path $archive.FullName -DestinationPath $extractDir -Force }
        catch { Write-Log "Ensure-Extracted FAIL on $($archive.Name): $_"; return $null }
    }
    $bin = Get-ChildItem $extractDir -Recurse -Filter "$BinaryName*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($bin) { return $bin.FullName }
    return $null
}

# Test-InternetAvailable — used by recon to gracefully degrade air-gapped
function Test-InternetAvailable {
    try {
        $r = Invoke-WebRequest -Uri 'https://1.1.1.1' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($r.StatusCode) { return $true }
    } catch { }
    try {
        $r = Test-NetConnection -ComputerName 'example.com' -Port 80 -WarningAction SilentlyContinue -InformationLevel Quiet
        return [bool]$r
    } catch { return $false }
}

# Convert-IPCidr — given an IP and prefix length, return network/CIDR
function Convert-IPCidr {
    param([string]$IP, [int]$Prefix)
    $ipBytes   = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    $maskBytes = [byte[]]@(0,0,0,0)
    for ($i = 0; $i -lt $Prefix; $i++) {
        $maskBytes[[Math]::Floor($i/8)] = $maskBytes[[Math]::Floor($i/8)] -bor (128 -shr ($i % 8))
    }
    $netBytes = for ($i = 0; $i -lt 4; $i++) { [byte]($ipBytes[$i] -band $maskBytes[$i]) }
    return ('{0}/{1}' -f ($netBytes -join '.'), $Prefix)
}
