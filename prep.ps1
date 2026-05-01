# Blue Team Toolkit - Windows entry point
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Script:ToolkitDir = $PSScriptRoot
$Script:OutputDir  = Join-Path $ToolkitDir 'output'
$Script:ToolsDir   = Join-Path $ToolkitDir 'tools'
$Script:LogFile    = Join-Path $OutputDir 'toolkit.log'
$null = New-Item -ItemType Directory -Force -Path $OutputDir, $ToolsDir

. (Join-Path $ToolkitDir 'lib\windows\common.ps1')

function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host " Blue Team Toolkit  --  Windows" -ForegroundColor Cyan
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host " Suggested order: 1 -> 6 -> 7 -> 3 -> 2/4"
        Write-Host ""
        Write-Host " 1) Install / Download Tools         (battle plan section R)"
        Write-Host " 6) Map / Discover this host         (writes facts.json; runs winpeas/autoruns/nmap if present)"
        Write-Host " 7) Recommendations punch list       (reads facts.json -> prioritized P0/P1/P2)"
        Write-Host " 3) Hardening Checklist (semi-auto)  (section J)"
        Write-Host " 2) Per-host Triage                  (section I; dispatches winpeas/autoruns)"
        Write-Host " 4) Backdoor Hunt                    (sections M / A; dispatches autoruns/chainsaw/pe-sieve/loki + CLEAR checks)"
        Write-Host " 9) Network Recon                    (section H; internal nmap + Shodan/DNS external)"
        Write-Host " 8) Findings history                 (persistent across runs)"
        Write-Host " 5) View action log"
        Write-Host " Q) Quit"
        Write-Host ""
        $c = Read-Host "Select"
        switch ($c.ToUpper()) {
            '1' { & (Join-Path $ToolkitDir 'lib\windows\installer.ps1') }
            '2' { & (Join-Path $ToolkitDir 'lib\windows\triage.ps1') }
            '3' { & (Join-Path $ToolkitDir 'lib\windows\harden.ps1') }
            '4' { & (Join-Path $ToolkitDir 'lib\windows\hunt.ps1') }
            '5' {
                if (Test-Path $LogFile) { Get-Content $LogFile -Tail 200 | Out-Host; Pause-Toolkit }
                else { Write-Host "No log entries yet."; Pause-Toolkit }
            }
            '6' { & (Join-Path $ToolkitDir 'lib\windows\map.ps1') }
            '7' { & (Join-Path $ToolkitDir 'lib\windows\recommend.ps1') }
            '8' { & (Join-Path $ToolkitDir 'lib\windows\findings.ps1') }
            '9' { & (Join-Path $ToolkitDir 'lib\windows\recon.ps1') }
            'Q' { return }
        }
    }
}

Show-Menu
