$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$out = Join-Path $Script:OutputDir ("hunt-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
Write-Log "HUNT start -> $out"

function H { param([string]$Title, [scriptblock]$B)
    "`n## $Title" | Tee-Object -Append -FilePath $out
    try { & $B 2>&1 | Out-File -Append -FilePath $out } catch { "[ERR] $_" | Out-File -Append -FilePath $out }
}

# --- Tool dispatch (run the actual hunting tools we installed) ---
H "Tool dispatch"

# Autoruns persistence dump
$autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'Autoruns\autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $autoruns) { $autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($autoruns) {
    $ar = Join-Path $Script:OutputDir ("autoruns-hunt-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'autorunsc' -LogFile $ar -FilePath $autoruns.FullName `
        -ArgumentList @('-nobanner','-accepteula','-a','*','-m','-h','-c')
    "Autoruns CSV (filter VerifiedSigner blank for unsigned): $ar" | Tee-Object -Append $out
    # Parse: lines with empty VerifiedSigner column = unsigned persistence
    Get-Content $ar -ErrorAction SilentlyContinue | Select-Object -Skip 1 | ForEach-Object {
        $cols = $_ -split ','
        if ($cols.Count -ge 8 -and ($cols[7] -eq '' -or $cols[7] -match 'Not signed|n/a')) {
            $entry = ($cols[2..4] -join ' / ')
            Record-Finding -Type 'autoruns_unsigned_entry' -Target ($entry.Substring(0, [Math]::Min($entry.Length,200))) -Extra @{ confidence = 'maybe' }
        }
    }
}

# chainsaw - Sigma rules over Windows event logs
$chainsaw = Get-ChildItem (Join-Path $Script:ToolsDir 'chainsaw*\chainsaw.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
$sigmaRules = Get-ChildItem (Join-Path $Script:ToolsDir 'sigma\rules\windows') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($chainsaw -and (Confirm-YesNo "Run chainsaw against C:\Windows\System32\winevt\Logs (5-15 min)?")) {
    $cs = Join-Path $Script:OutputDir ("chainsaw-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    $sigmaArg = if ($sigmaRules) { @('-s', (Join-Path $Script:ToolsDir 'sigma\rules\windows')) } else { @() }
    $args = @('hunt', "$env:SystemRoot\System32\winevt\Logs", '--csv', '--output', $cs) + $sigmaArg
    Invoke-Silent -Label 'chainsaw' -LogFile "$cs.log" -FilePath $chainsaw.FullName -ArgumentList $args
    Get-Content $cs -ErrorAction SilentlyContinue | Select-Object -Skip 1 | ForEach-Object {
        $cols = $_ -split ','
        if ($cols.Count -ge 2) {
            Record-Finding -Type 'chainsaw_alert' -Target ($cols[1] -replace '"','') -Extra @{ confidence = 'clear' }
        }
    }
}

# hayabusa - alt event log scanner
$hayabusa = Get-ChildItem (Join-Path $Script:ToolsDir 'hayabusa*\hayabusa*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($hayabusa -and -not $chainsaw -and (Confirm-YesNo 'Run hayabusa csv-timeline?')) {
    $hb = Join-Path $Script:OutputDir ("hayabusa-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'hayabusa' -LogFile "$hb.log" -FilePath $hayabusa.FullName `
        -ArgumentList @('csv-timeline','-d',"$env:SystemRoot\System32\winevt\Logs",'-o',$hb,'-q')
}

# hollows_hunter - in-memory injection sweep (Meterpreter signature)
$hh = Get-ChildItem (Join-Path $Script:ToolsDir 'hollows_hunter*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($hh) {
    $hho = Join-Path $Script:OutputDir ("hollowshunter-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    New-Item -ItemType Directory -Force -Path $hho | Out-Null
    Push-Location $hho
    & $hh.FullName /shellc /imp 3 /data 1 /quiet | Out-Null
    Pop-Location
    "hollows_hunter dump dir: $hho" | Tee-Object -Append $out
    Get-ChildItem $hho -Recurse -Filter '*.dmp' -ErrorAction SilentlyContinue | ForEach-Object {
        Record-Finding -Type 'hollows_hunter_dump' -Target $_.FullName -Extra @{ confidence = 'clear' }
    }
}

# Loki IOC scan
$loki = Get-ChildItem (Join-Path $Script:ToolsDir 'loki*\loki.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($loki -and (Confirm-YesNo 'Run Loki IOC scan against C:\ (30-60 min)?')) {
    $lk = Join-Path $Script:OutputDir ("loki-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Invoke-Silent -Label 'loki' -LogFile $lk -FilePath $loki.FullName -ArgumentList @('-p','C:\','--noprocscan')
    Select-String -Path $lk -Pattern 'ALERT' -ErrorAction SilentlyContinue | ForEach-Object {
        Record-Finding -Type 'loki_alert' -Target ($_.Line.Substring(0, [Math]::Min($_.Line.Length, 200))) -Extra @{ confidence = 'clear' }
    }
}

"`n[hunt] dispatch done; running CLEAR backdoor checks..." | Tee-Object -Append $out

# ============================================================
# CLEAR backdoors — high specificity
# ============================================================

H "[CLEAR] Local accounts created in last 30 days" {
    try {
        Get-LocalUser | Where-Object { $_.PasswordLastSet -and ([datetime]$_.PasswordLastSet -gt (Get-Date).AddDays(-30)) } | ForEach-Object {
            $line = "$($_.Name) created/pw-set $($_.PasswordLastSet)"
            Write-Output $line
            Record-Finding -Type 'recent_local_account' -Target $_.Name -Extra @{ confidence = 'clear'; pw_last_set = "$($_.PasswordLastSet)" }
        }
    } catch { }
}

H "[CLEAR] Local accounts with PasswordNeverExpires + Enabled" {
    try {
        Get-LocalUser | Where-Object { $_.PasswordNeverExpires -and $_.Enabled } | ForEach-Object {
            Write-Output "$($_.Name) (no expiry, enabled)"
            Record-Finding -Type 'pw_never_expires_account' -Target $_.Name -Extra @{ confidence = 'maybe' }
        }
    } catch { }
}

H "[CLEAR] Services with binPath in C:\Users or C:\ProgramData" {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'C:\\(Users|ProgramData|Temp)\\' } | ForEach-Object {
        $line = "$($_.Name) -> $($_.PathName)"
        Write-Output $line
        Record-Finding -Type 'service_in_user_or_programdata' -Target $_.Name -Extra @{ confidence = 'clear'; path = $_.PathName }
    }
}

H "[CLEAR] Scheduled tasks with action in writable dirs" {
    Get-ScheduledTask | ForEach-Object {
        $exe = $_.Actions.Execute
        if ($exe -and $exe -match 'C:\\(Users|ProgramData|Temp|Windows\\Temp)\\') {
            $line = "$($_.TaskPath)$($_.TaskName) -> $exe"
            Write-Output $line
            Record-Finding -Type 'task_in_writable_dir' -Target "$($_.TaskPath)$($_.TaskName)" -Extra @{ confidence = 'clear'; action = $exe }
        }
    }
}

H "[CLEAR] Services running as LocalSystem outside System32" {
    Get-CimInstance Win32_Service | Where-Object {
        $_.StartName -eq 'LocalSystem' -and $_.PathName -and
        $_.PathName -notmatch [regex]::Escape("$env:SystemRoot\System32") -and
        $_.PathName -notmatch [regex]::Escape("$env:ProgramFiles") -and
        $_.PathName -notmatch [regex]::Escape("${env:ProgramFiles(x86)}")
    } | ForEach-Object {
        Write-Output "$($_.Name) [$($_.StartName)] -> $($_.PathName)"
        Record-Finding -Type 'localsystem_service_outside_system32' -Target $_.Name -Extra @{ confidence = 'clear'; path = $_.PathName }
    }
}

H "[CLEAR] Defender disabled / tamper protection off" {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            Write-Output "Defender real-time monitoring is DISABLED"
            Record-Finding -Type 'defender_realtime_disabled' -Target 'Get-MpComputerStatus' -Extra @{ confidence = 'clear' }
        }
        if (-not $mp.IsTamperProtected) {
            Write-Output "Defender tamper protection is OFF"
            Record-Finding -Type 'defender_tamper_off' -Target 'Get-MpComputerStatus' -Extra @{ confidence = 'maybe' }
        }
        if (-not $mp.AntivirusEnabled) {
            Write-Output "Defender AV ENGINE is disabled"
            Record-Finding -Type 'defender_av_disabled' -Target 'Get-MpComputerStatus' -Extra @{ confidence = 'clear' }
        }
    } catch { }
}

H "[CLEAR] Defender exclusions added (rootkit indicator)" {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        foreach ($p in $pref.ExclusionPath) {
            Write-Output "ExclusionPath: $p"
            Record-Finding -Type 'defender_exclusion' -Target $p -Extra @{ confidence = 'maybe'; kind = 'path' }
        }
        foreach ($p in $pref.ExclusionProcess) {
            Write-Output "ExclusionProcess: $p"
            Record-Finding -Type 'defender_exclusion' -Target $p -Extra @{ confidence = 'maybe'; kind = 'process' }
        }
        foreach ($p in $pref.ExclusionExtension) {
            Write-Output "ExclusionExtension: $p"
            Record-Finding -Type 'defender_exclusion' -Target $p -Extra @{ confidence = 'maybe'; kind = 'extension' }
        }
    } catch { }
}

H "[CLEAR] Suspicious listening ports (known malware/C2 defaults)" {
    $bad = 4444, 4443, 1337, 31337, 6666, 6667, 8888, 9999, 12345, 54321
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $bad } | ForEach-Object {
        $line = "$($_.LocalAddress):$($_.LocalPort) PID=$($_.OwningProcess)"
        Write-Output $line
        Record-Finding -Type 'suspicious_listen_port' -Target ("$($_.LocalAddress):$($_.LocalPort)") -Extra @{ confidence = 'clear'; pid = $_.OwningProcess }
    }
}

H "[CLEAR] Recent Domain Admins / Enterprise Admins additions" {
    foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins') {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop
            foreach ($m in $members) {
                try {
                    $u = Get-ADUser -Identity $m.SamAccountName -Properties whenChanged -ErrorAction Stop
                    if ($u.whenChanged -and $u.whenChanged -gt (Get-Date).AddDays(-30)) {
                        Write-Output "$g <- $($u.SamAccountName) (changed $($u.whenChanged))"
                        Record-Finding -Type 'recent_privileged_group_change' -Target "$g/$($u.SamAccountName)" -Extra @{ confidence = 'clear' }
                    }
                } catch { }
            }
        } catch { }
    }
}

H "[CLEAR] Backup Operators members (CyLG kill-chain step 4)" {
    try {
        $mems = Get-LocalGroupMember -Group 'Backup Operators' -ErrorAction SilentlyContinue
        foreach ($m in $mems) {
            Write-Output "Backup Operators <- $($m.Name)"
            Record-Finding -Type 'backup_operators_member' -Target $m.Name -Extra @{ confidence = 'clear' }
        }
    } catch { }
    try {
        $admems = Get-ADGroupMember -Identity 'Backup Operators' -Recursive -ErrorAction Stop
        foreach ($m in $admems) {
            Write-Output "AD Backup Operators <- $($m.SamAccountName)"
            Record-Finding -Type 'backup_operators_member' -Target $m.SamAccountName -Extra @{ confidence = 'clear'; source = 'AD' }
        }
    } catch { }
}

H "[CLEAR] AppInit_DLLs populated (legacy DLL injection)" {
    try {
        $v = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction Stop
        if ($v.AppInit_DLLs) {
            Write-Output "AppInit_DLLs = $($v.AppInit_DLLs)"
            Record-Finding -Type 'appinit_dlls_set' -Target $v.AppInit_DLLs -Extra @{ confidence = 'clear'; load = $v.LoadAppInit_DLLs }
        }
    } catch { }
}

H "[CLEAR] WMI persistence (FilterToConsumerBinding present)" {
    try {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
            Write-Output "$($_.Filter) -> $($_.Consumer)"
            Record-Finding -Type 'wmi_persistence' -Target ("$($_.Filter) -> $($_.Consumer)") -Extra @{ confidence = 'clear' }
        }
    } catch { }
}

"`n[hunt] CLEAR checks done; running MAYBE / CyLG-specific checks..." | Tee-Object -Append $out

H "printer.exe / printer.* (CyLG known backdoor)" {
    Get-ChildItem -Path C:\ -Recurse -Include printer.exe, printer.dll, printer.bat, printer.ps1 -ErrorAction SilentlyContinue 2>$null
}
H "services with 'printer' in path (excluding spoolsv.exe)" {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*printer*" -and $_.PathName -notlike "*spoolsv*" }
}
H "scheduled tasks calling printer*" {
    Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*printer*" }
}
H "running printer* processes" { Get-Process printer* -ErrorAction SilentlyContinue }

H "binaries dropped in suspicious dirs (last 30d)" {
    @('C:\Users\Public', 'C:\Windows\Temp', 'C:\ProgramData') | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -Include *.exe, *.dll, *.ps1, *.bat, *.vbs, *.hta -ErrorAction SilentlyContinue |
            Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) |
            Select-Object FullName, Length, LastWriteTime
    }
}
H "system process masquerading (svchost/lsass/csrss/winlogon outside System32)" {
    Get-Process svchost, lsass, csrss, winlogon -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot\System32\*" } |
        Select-Object Name, Id, Path
}
H "services with binPath in C:\Users or C:\ProgramData" {
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -match 'C:\\(Users|ProgramData)\\' } |
        Select-Object Name, PathName, StartMode, State
}
H "Run keys" {
    @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Image File Execution Options'
    ) | ForEach-Object { "--- $_ ---"; Get-ItemProperty $_ -ErrorAction SilentlyContinue }
}
H "WMI persistence" {
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventFilter           -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer         -ErrorAction SilentlyContinue
}
H "AppInit_DLLs" {
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue |
        Select-Object AppInit_DLLs, LoadAppInit_DLLs
}
H "BITS jobs"  { bitsadmin /list /allusers /verbose 2>$null }
H "hosts file" { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

H "Exchange / IIS web shell paths (recent .aspx/.dll, last 90d)" {
    $paths = @(
        'C:\inetpub\wwwroot',
        'C:\inetpub\wwwroot\aspnet_client',
        'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth',
        'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Recurse $p -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.aspx', '.asp', '.ashx', '.dll' -and
                               $_.LastWriteTime -gt (Get-Date).AddDays(-90) } |
                Select-Object FullName, LastWriteTime, Length
        }
    }
}

H "local admins" { net localgroup Administrators }
H "Backup Operators (CyLG kill-chain step 4 priority)" {
    try { net localgroup "Backup Operators" } catch { }
    try { Get-ADGroupMember "Backup Operators" -ErrorAction SilentlyContinue } catch { }
}
H "users created in last 30d (local + AD if available)" {
    try { Get-LocalUser | Where-Object { $_.PasswordLastSet -and ([datetime]$_.PasswordLastSet -gt (Get-Date).AddDays(-30)) } } catch { }
    try { Get-ADUser -Filter * -Properties whenCreated -ErrorAction SilentlyContinue |
            Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-30) } |
            Select-Object SamAccountName, whenCreated } catch { }
}
H "DCSync rights audit (run on DC, requires AD module)" {
    try {
        $rootDSE = (Get-ADRootDSE).defaultNamingContext
        $acl = Get-Acl ("AD:\" + $rootDSE)
        $acl.Access | Where-Object {
            $_.ObjectType -in [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                              [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
                              [Guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        } | Select-Object IdentityReference, AccessControlType, ObjectType
    } catch { "(not on DC or AD module not available)" }
}
H "DSRM admin sync (Skeleton-Key-style)" {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue |
        Select-Object DsrmAdminLogonBehavior
}

H "Drift vs persistence baseline (if present)" {
    $b1 = Join-Path $Script:OutputDir 'baseline-runkeys.txt'
    $b2 = Join-Path $Script:OutputDir 'baseline-services.txt'
    $b3 = Join-Path $Script:OutputDir 'baseline-tasks.txt'

    if (Test-Path $b1) {
        $now = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        ) | ForEach-Object { "--- $_ ---"; Get-ItemProperty $_ -ErrorAction SilentlyContinue } | Out-String
        $diff = Compare-Object (Get-Content $b1) ($now -split "`n")
        if ($diff) { "Run-key drift:"; $diff } else { "Run keys: no drift" }
    } else { "(no run-key baseline; create via Hardening menu step 'Snapshot persistence baseline')" }

    if (Test-Path $b2) {
        $now = Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode | Out-String
        $diff = Compare-Object (Get-Content $b2) ($now -split "`n")
        if ($diff) { "Service drift:"; $diff } else { "Services: no drift" }
    }

    if (Test-Path $b3) {
        $now = Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{n='Action';e={$_.Actions.Execute}} | Out-String
        $diff = Compare-Object (Get-Content $b3) ($now -split "`n")
        if ($diff) { "Scheduled-task drift:"; $diff } else { "Tasks: no drift" }
    }
}

Write-Log "HUNT done -> $out"
Write-Host "`nHunt written: $out" -ForegroundColor Green
Write-Host "`nFor any hits (process from §A):" -ForegroundColor Yellow
Write-Host " 1. DO NOT delete  2. Get-FileHash + copy to evidence"
Write-Host " 3. Network-isolate the host"
Write-Host " 4. Find ALL hosts with same hash (Velociraptor)"
Write-Host " 5. Eradicate fleet-wide simultaneously"
Write-Host " 6. Patch the entry point   7. Log to #log + report to white cell"
Pause-Toolkit
