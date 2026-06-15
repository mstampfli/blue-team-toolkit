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
        Write-Host " Workflow order: 1 install, 2 map, 3 recommend, 4 harden, then 5/6 triage/hunt."
        Write-Host ""
        Write-Host " 1) Install / download tools         (from tools.json)"
        Write-Host " 2) Map / discover this host         (writes facts.json; winpeas/autoruns/nmap if present)"
        Write-Host " 3) Recommendations punch list       (reads facts.json -> prioritized P0/P1/P2)"
        Write-Host " 4) Hardening checklist              (semi-auto, dry-run by default)"
        Write-Host " 5) Per-host triage                  (live state; dispatches winpeas/autoruns)"
        Write-Host " 6) Backdoor / persistence hunt      (autoruns/chainsaw/pe-sieve/loki + structured checks)"
        Write-Host " 7) Network recon                    (internal nmap + external Shodan/DNS)"
        Write-Host " 8) Findings history                 (persistent across runs)"
        Write-Host " 9) Security report card             (graded HTML + Markdown from facts + findings)"
        Write-Host " L) View action log"
        Write-Host " Q) Quit"
        Write-Host ""
        $c = Read-Host "Select"
        switch ($c.ToUpper()) {
            '1' { & (Join-Path $ToolkitDir 'lib\windows\installer.ps1') }
            '2' { & (Join-Path $ToolkitDir 'lib\windows\map.ps1') }
            '3' { & (Join-Path $ToolkitDir 'lib\windows\recommend.ps1') }
            '4' { & (Join-Path $ToolkitDir 'lib\windows\harden.ps1') }
            '5' { & (Join-Path $ToolkitDir 'lib\windows\triage.ps1') }
            '6' { & (Join-Path $ToolkitDir 'lib\windows\hunt.ps1') }
            '7' { & (Join-Path $ToolkitDir 'lib\windows\recon.ps1') }
            '8' { & (Join-Path $ToolkitDir 'lib\windows\findings.ps1') }
            '9' { & (Join-Path $ToolkitDir 'lib\windows\report.ps1') }
            'L' {
                if (Test-Path $LogFile) { Get-Content $LogFile -Tail 200 | Out-Host; Pause-Toolkit }
                else { Write-Host "No log entries yet."; Pause-Toolkit }
            }
            'Q' { return }
        }
    }
}

Show-Menu
