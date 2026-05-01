$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Test-Admin)) {
    Write-Host "ERROR: must run elevated (right-click PowerShell -> Run as Administrator)." -ForegroundColor Red
    Pause-Toolkit; return
}

Write-Host "Hardening mode:"
Write-Host "  1) DRY-RUN (recommended first pass)"
Write-Host "  2) Apply with per-step confirmation (semi-auto)"
$mode = Read-Host "Pick"
$DryRun = ($mode -ne '2')
Write-Log "HARDEN start (DryRun=$DryRun)"

# Each item: hashtable with Label, Check (scriptblock), Apply (scriptblock), Rollback (string)
$items = @(
    @{
        Label    = "LSA Protection (RunAsPPL=1) -- breaks Mimikatz LSASS read"
        Check    = { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL }
        Apply    = { New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -PropertyType DWord -Force | Out-Null }
        Rollback = "Remove RunAsPPL value from same key, then reboot"
    },
    @{
        Label    = "Disable SMBv1 (EternalBlue family)"
        Check    = { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State }
        Apply    = { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
        Rollback = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    },
    @{
        Label    = "Require SMB signing (server side)"
        Check    = { (Get-SmbServerConfiguration).RequireSecuritySignature }
        Apply    = { Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false }
        Rollback = "Set-SmbServerConfiguration -RequireSecuritySignature `$false"
    },
    @{
        Label    = "Disable SMBv3 compression (SMBGhost CVE-2020-0796 workaround)"
        Check    = { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).DisableCompression }
        Apply    = { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'DisableCompression' -Type DWord -Value 1 }
        Rollback = "Set the same value back to 0"
    },
    @{
        Label    = "Disable Print Spooler (PrintNightmare -- DO THIS ON DCs)"
        Check    = { (Get-Service Spooler).Status }
        Apply    = { Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled }
        Rollback = "Set-Service Spooler -StartupType Automatic; Start-Service Spooler"
    },
    @{
        Label    = "Disable LLMNR via policy"
        Check    = { (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast }
        Apply    = {
            New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
            Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0
        }
        Rollback = "Remove EnableMulticast value"
    },
    @{
        Label    = "Disable NetBIOS over TCP/IP on every adapter"
        Check    = { Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | Select-Object Description, TcpipNetbiosOptions }
        Apply    = { Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null } }
        Rollback = "Re-set TcpipNetbios to 0 (default)"
    },
    @{
        Label    = "Disable WPAD service (WinHttpAutoProxySvc)"
        Check    = { (Get-Service WinHttpAutoProxySvc -ErrorAction SilentlyContinue).Status }
        Apply    = { Stop-Service WinHttpAutoProxySvc -Force -ErrorAction SilentlyContinue; Set-Service WinHttpAutoProxySvc -StartupType Disabled }
        Rollback = "Set-Service WinHttpAutoProxySvc -StartupType Manual"
    },
    @{
        Label    = "LmCompatibilityLevel = 5 (NTLMv2 only)"
        Check    = { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LmCompatibilityLevel }
        Apply    = { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5 }
        Rollback = "Set value back to 3 (default)"
    },
    @{
        Label    = "PowerShell ScriptBlockLogging on"
        Check    = { (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging }
        Apply    = {
            New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
            Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Type DWord -Value 1
        }
        Rollback = "Set to 0"
    },
    @{
        Label    = "PowerShell ModuleLogging (* modules)"
        Check    = { (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging }
        Apply    = {
            New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null
            Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Type DWord -Value 1
            New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
            Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*'
        }
        Rollback = "Disable EnableModuleLogging"
    },
    @{
        Label    = "Block outbound SMB to internet (TCP 445)"
        Check    = { Get-NetFirewallRule -DisplayName 'Block outbound SMB to Internet' -ErrorAction SilentlyContinue }
        Apply    = {
            New-NetFirewallRule -DisplayName 'Block outbound SMB to Internet' `
                -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 `
                -Profile Public, Domain, Private -Enabled True | Out-Null
        }
        Rollback = "Remove-NetFirewallRule -DisplayName 'Block outbound SMB to Internet'"
    },
    @{
        Label    = "Audit policy: Logon, Process Creation, Cred Validation, Special Logon, Object Access (sensitive)"
        Check    = { auditpol /get /category:* | Select-String 'Logon|Process Creation|Credential Validation|Special Logon' }
        Apply    = {
            auditpol /set /subcategory:"Logon"               /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Process Creation"    /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Process Termination" /success:enable                 | Out-Null
            auditpol /set /subcategory:"Special Logon"       /success:enable                 | Out-Null
            auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Account Lockout"     /success:enable /failure:enable | Out-Null
        }
        Rollback = "auditpol /clear (be careful)"
    },
    @{
        Label    = "Defender: enable real-time monitoring (tamper protection must be set in UI)"
        Check    = { Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected }
        Apply    = { Set-MpPreference -DisableRealtimeMonitoring $false }
        Rollback = "Set-MpPreference -DisableRealtimeMonitoring `$true"
    },
    @{
        Label    = "Snapshot persistence baseline (Run keys + Services + Tasks)"
        Check    = { if (Test-Path "$Script:OutputDir\baseline-runkeys.txt") { 'baseline exists' } else { 'no baseline yet' } }
        Apply    = {
            $keys = @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            $keys | ForEach-Object { "--- $_ ---"; Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
                Out-File "$Script:OutputDir\baseline-runkeys.txt"
            Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode |
                Out-File "$Script:OutputDir\baseline-services.txt"
            Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{n='Action';e={$_.Actions.Execute}} |
                Out-File "$Script:OutputDir\baseline-tasks.txt"
        }
        Rollback = "Delete baseline-*.txt files"
    }
)

foreach ($item in $items) {
    Write-Host "`n----- $($item.Label) -----" -ForegroundColor Cyan
    try {
        $current = & $item.Check
        Write-Host "Current : $current"
    } catch { Write-Host "Check error: $_" -ForegroundColor Yellow }
    Write-Host "Rollback: $($item.Rollback)" -ForegroundColor DarkGray

    if ($DryRun) {
        Write-Host "[DRY-RUN] not executed."
        Write-Log "DRY: would apply: $($item.Label)"
        Read-Host "Press Enter (q to quit)" | ForEach-Object { if ($_ -eq 'q') { return } }
        continue
    }

    if (Confirm-YesNo "Apply this step?") {
        try {
            & $item.Apply
            Write-Host "Applied." -ForegroundColor Green
            Write-Log "APPLY OK: $($item.Label)"
        } catch {
            Write-Host "FAILED: $_" -ForegroundColor Red
            Write-Log "APPLY FAIL: $($item.Label) -- $_"
        }
    } else {
        Write-Log "SKIP: $($item.Label)"
    }
}

Write-Host "`nHardening pass complete (DryRun=$DryRun)." -ForegroundColor Green
Pause-Toolkit
