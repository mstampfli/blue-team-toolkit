$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$out = Join-Path $Script:OutputDir ("triage-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
Write-Log "TRIAGE start -> $out"

function Section {
    param([string]$Label, [scriptblock]$Block)
    "`n===== $Label =====" | Out-File -Append -FilePath $out
    try { & $Block 2>&1 | Out-File -Append -FilePath $out }
    catch { "[ERR] $_" | Out-File -Append -FilePath $out }
}

# --- Tool dispatch (run installed tools first) ---
Write-Host "[triage] dispatching to installed tools..." -ForegroundColor Cyan

$winpeas = Get-ChildItem (Join-Path $Script:ToolsDir 'winPEAS*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($winpeas -and (Confirm-YesNo 'Run WinPEAS for privesc surface (~3 min)?')) {
    $wp = Join-Path $Script:OutputDir ("winpeas-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'winpeas' -LogFile $wp -FilePath $winpeas.FullName -ArgumentList @()
    Section 'WinPEAS (see file)' { "Output: $wp" }
}

$autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'Autoruns\autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $autoruns) { $autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($autoruns) {
    $ar = Join-Path $Script:OutputDir ("autoruns-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'autorunsc' -LogFile $ar -FilePath $autoruns.FullName `
        -ArgumentList @('-nobanner','-accepteula','-a','*','-m','-h','-c')
    Section 'Autoruns persistence dump' { "Output: $ar (open in Excel; sort by VerifiedSigner blank)" }
}

$sigcheck = Get-ChildItem (Join-Path $Script:ToolsDir '*Sigcheck*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sigcheck) {
    $sc = Join-Path $Script:OutputDir ("sigcheck-system32-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'sigcheck' -LogFile $sc -FilePath $sigcheck.FullName `
        -ArgumentList @('-nobanner','-accepteula','-e','-u','-s',"$env:SystemRoot\System32")
    Section 'Sigcheck unsigned in System32' { "Output: $sc" }
}

Write-Host "[triage] dispatch done; collecting raw state..." -ForegroundColor Cyan

Section "host info"            { Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, CsDomain, CsManufacturer | Format-List }
Section "logged on"            { query user 2>$null; Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message }
Section "listening sockets"    { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table -AutoSize }
Section "established outbound" { Get-NetTCPConnection -State Established | Format-Table -AutoSize }
Section "processes"            { Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine | Format-Table -AutoSize }
Section "scheduled tasks (enabled)" { Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskPath, TaskName, State | Format-Table -AutoSize }
Section "services in odd paths" {
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and
        $_.PathName -notlike "*\Windows\*" -and
        $_.PathName -notlike "*Program Files*"
    } | Format-Table Name, PathName, StartMode, State -AutoSize
}
Section "Run keys" {
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Image File Execution Options'
    )
    $keys | ForEach-Object { "--- $_ ---"; Get-ItemProperty $_ -ErrorAction SilentlyContinue }
}
Section "WMI persistence" {
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventFilter           -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer         -ErrorAction SilentlyContinue
}
Section "local admins" { net localgroup Administrators }
Section "printer.exe hunt (CyLG known backdoor)" {
    Get-ChildItem -Path C:\ -Recurse -Include printer.exe, printer.dll, printer.bat, printer.ps1 -ErrorAction SilentlyContinue 2>$null
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*printer*" -and $_.PathName -notlike "*spoolsv*" }
    Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*printer*" }
    Get-Process printer* -ErrorAction SilentlyContinue
}
Section "drops in Public/Temp/ProgramData (last 30d)" {
    @('C:\Users\Public', 'C:\Windows\Temp', 'C:\ProgramData') | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -Include *.exe, *.dll, *.ps1, *.bat, *.vbs, *.hta -ErrorAction SilentlyContinue |
            Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) |
            Select-Object FullName, Length, LastWriteTime
    }
}
Section "system process masquerading" {
    Get-Process svchost, lsass, csrss, winlogon -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot\System32\*" } |
        Select-Object Name, Id, Path
}
Section "BITS jobs"     { bitsadmin /list /allusers /verbose 2>$null }
Section "hosts file"    { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }
Section "AppInit DLLs"  { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs, LoadAppInit_DLLs }
Section "Defender status" {
    Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, IsTamperProtected, AntispywareEnabled
}
Section "SMB1 enabled?" { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object FeatureName, State }
Section "LSA Protection (RunAsPPL)" { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue | Select-Object RunAsPPL, RunAsPPLBoot }
Section "Credential Guard status" {
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue |
        Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus
}
Section "PowerShell logging policy" {
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' | ForEach-Object {
        "--- $_ ---"
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    }
}
Section "Sysmon present?" { Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue }
Section "recent .aspx in IIS / Exchange paths (last 90d)" {
    $paths = @(
        'C:\inetpub\wwwroot',
        'C:\inetpub\wwwroot\aspnet_client',
        'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Recurse $p -Include *.aspx, *.asp, *.ashx -ErrorAction SilentlyContinue |
                Where-Object LastWriteTime -gt (Get-Date).AddDays(-90) |
                Select-Object FullName, LastWriteTime, Length
        }
    }
}
Section "Backup Operators members" { try { net localgroup "Backup Operators" } catch { } }

Write-Log "TRIAGE done -> $out"
Write-Host "Triage written: $out" -ForegroundColor Green
Pause-Toolkit
