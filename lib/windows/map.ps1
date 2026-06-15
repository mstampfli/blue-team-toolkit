# Discovery / map mode. Writes $Script:OutputDir\facts.json.
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$facts = [ordered]@{}
Write-Log "MAP start"

$os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue

$facts.host       = $env:COMPUTERNAME
$facts.platform   = 'windows'
$facts.scanned_at = (Get-Date).ToString('o')
$facts.os = @{
    product = $os.Caption
    version = $os.Version
    build   = $os.BuildNumber
    arch    = $os.OSArchitecture
    install_date = $os.InstallDate
}

# Role detection
function Has-Service { param($n) $null -ne (Get-Service $n -ErrorAction SilentlyContinue) }
function Svc-Running { param($n) (Get-Service $n -ErrorAction SilentlyContinue).Status -eq 'Running' }

$isDC = $false
try {
    $f = Get-WindowsFeature -Name 'AD-Domain-Services' -ErrorAction SilentlyContinue
    if ($f) { $isDC = $f.Installed }
} catch { }
if (-not $isDC) {
    $isDC = (Has-Service 'NTDS') -or (Has-Service 'Kdc')
}

$facts.role = @{
    domain_role        = $cs.DomainRole       # 0=Standalone WS, 1=Member WS, 2=Standalone Server, 3=Member Server, 4=Backup DC, 5=Primary DC
    ad_joined          = [bool]$cs.PartOfDomain
    domain             = $cs.Domain
    is_dc              = $isDC
    iis                = (Has-Service 'W3SVC')
    iis_running        = (Svc-Running 'W3SVC')
    exchange           = (Test-Path 'C:\Program Files\Microsoft\Exchange Server')
    adcs               = (Has-Service 'CertSvc')
    sql_server         = (Has-Service 'MSSQLSERVER') -or ((Get-Service 'MSSQL*' -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
    rdp_listening      = $null -ne (Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue)
    winrm_listening    = $null -ne (Get-NetTCPConnection -LocalPort 5985, 5986 -State Listen -ErrorAction SilentlyContinue)
    print_spooler      = (Svc-Running 'Spooler')
    hyperv             = (Has-Service 'vmms')
    veeam              = ((Get-Service 'Veeam*' -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
}

# Security state
$lsa  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$dnsc = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
$psbl = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
$pml  = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
$ptr  = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
$smbsrv = try { Get-SmbServerConfiguration -ErrorAction SilentlyContinue } catch { $null }
$smb1   = try { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State } catch { 'unknown' }
$mp     = try { Get-MpComputerStatus -ErrorAction SilentlyContinue } catch { $null }
$dg     = try { Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue } catch { $null }
$smb3comp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).DisableCompression

$facts.security_state = @{
    lsa_protection_runasppl = $lsa.RunAsPPL
    lm_compat_level         = $lsa.LmCompatibilityLevel
    smb1_state              = "$smb1"
    smb_signing_required    = $smbsrv.RequireSecuritySignature
    smb3_compression_disabled = $smb3comp
    spooler_running         = (Svc-Running 'Spooler')
    wpad_running            = (Svc-Running 'WinHttpAutoProxySvc')
    llmnr_disabled          = ($dnsc.EnableMulticast -eq 0)
    defender_realtime       = $mp.RealTimeProtectionEnabled
    defender_tamper         = $mp.IsTamperProtected
    defender_antivirus      = $mp.AntivirusEnabled
    sysmon_running          = ((Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running' | Measure-Object).Count -gt 0)
    ps_scriptblock_logging  = ($psbl.EnableScriptBlockLogging -eq 1)
    ps_module_logging       = ($pml.EnableModuleLogging -eq 1)
    ps_transcription        = ($ptr.EnableTranscripting -eq 1)
    credential_guard_running = if ($dg) { ($dg.SecurityServicesRunning -contains 1) } else { $null }
    vbs_status              = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { $null }
}

# Listening ports + bind-interface analysis
$lconns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$facts.listening_ports = @($lconns | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
$facts.listening_detailed = @(
    $lconns | ForEach-Object {
        $expo = if ($_.LocalAddress -in '0.0.0.0','::') { 'all_interfaces' }
                elseif ($_.LocalAddress -in '127.0.0.1','::1') { 'localhost_only' }
                else { 'specific_interface' }
        [PSCustomObject]@{
            port     = $_.LocalPort
            bind     = $_.LocalAddress
            exposure = $expo
            pid      = $_.OwningProcess
        }
    }
)
$exposedAll = ($facts.listening_detailed | Where-Object { $_.exposure -eq 'all_interfaces' } | Measure-Object).Count

# Privileged-services audit + firewall posture
$svcRoot = (Get-CimInstance Win32_Service | Where-Object {
    $_.StartName -in 'LocalSystem','NT AUTHORITY\SYSTEM' -and $_.PathName -and
    $_.PathName -notmatch [regex]::Escape("$env:SystemRoot\System32") -and
    $_.PathName -notmatch [regex]::Escape("$env:ProgramFiles") -and
    $_.PathName -notmatch [regex]::Escape("${env:ProgramFiles(x86)}")
} | Measure-Object).Count

$fwInbound = try { (Get-NetFirewallProfile | Where-Object Enabled -eq $true | Measure-Object).Count } catch { 0 }
$fwAnyAllow = try { (Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound -ErrorAction SilentlyContinue |
    Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -eq 'Any' } | Measure-Object).Count } catch { 0 }

$facts.exposure = @{
    ports_bound_all_interfaces                   = $exposedAll
    services_localsystem_outside_standard_paths  = $svcRoot
    firewall_profiles_enabled                    = $fwInbound
    firewall_inbound_allow_any_rules             = $fwAnyAllow
    defender_realtime                            = $facts.security_state.defender_realtime
    defender_tamper                              = $facts.security_state.defender_tamper
}

# Tools present (in $ToolsDir)
$toolPaths = @{
    'velociraptor' = 'velociraptor*windows*.exe'
    'chainsaw'     = 'chainsaw*'
    'hayabusa'     = 'hayabusa*'
    'autoruns'     = 'Autoruns*'
    'sysinternals' = 'SysinternalsSuite*'
    'sysmon'       = 'Sysmon*'
    'winpeas'      = 'winPEAS*'
    'pesieve'      = 'pe-sieve*.exe'
    'hollowshunter'= 'hollows_hunter*.exe'
    'sharphound'   = 'SharpHound*'
    'nuclei'       = 'nuclei*'
    'loki'         = 'loki*'
    'yara'         = 'yara*'
    'winpmem'      = 'winpmem*'
    'sysmon-config'= 'sysmon-config\*'
    'sigma'        = 'sigma\*'
}
$tools = @()
foreach ($k in $toolPaths.Keys) {
    if (Get-ChildItem (Join-Path $Script:ToolsDir $toolPaths[$k]) -ErrorAction SilentlyContinue) { $tools += $k }
}
foreach ($cmd in 'nmap','git','python','pipx','pip') {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { $tools += $cmd }
}
$facts.tools_present = $tools | Sort-Object -Unique

# Persistence drift snapshot reference
$facts.baselines = @{
    runkeys  = (Test-Path (Join-Path $Script:OutputDir 'baseline-runkeys.txt'))
    services = (Test-Path (Join-Path $Script:OutputDir 'baseline-services.txt'))
    tasks    = (Test-Path (Join-Path $Script:OutputDir 'baseline-tasks.txt'))
}

$factsPath = Join-Path $Script:OutputDir 'facts.json'
$facts | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $factsPath
Write-Log "MAP wrote $factsPath"
Write-Host "facts.json written: $factsPath" -ForegroundColor Green

# Optional heavy passes
if (Test-Path (Join-Path $Script:ToolsDir 'winPEASx64.exe')) {
    if (Confirm-YesNo "Run WinPEAS for privesc surface (~3 min)?") {
        $wp = Join-Path $Script:OutputDir ("winpeas-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
        & (Join-Path $Script:ToolsDir 'winPEASx64.exe') > $wp
        Write-Log "winpeas -> $wp"
        Write-Host "WinPEAS output: $wp" -ForegroundColor Green
    }
}

$autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $autoruns) { $autoruns = Get-ChildItem (Join-Path $Script:ToolsDir 'Autoruns\autorunsc*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($autoruns) {
    if (Confirm-YesNo "Run autorunsc.exe -a * -m -h -c (full persistence dump)?") {
        $ar = Join-Path $Script:OutputDir ("autoruns-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
        Invoke-Silent -Label 'autorunsc' -LogFile $ar -FilePath $autoruns.FullName `
            -ArgumentList @('-nobanner','-accepteula','-a','*','-m','-h','-c')
        Write-Log "autorunsc -> $ar"
        Write-Host "Autoruns CSV: $ar" -ForegroundColor Green
    }
}

if (Get-Command nmap -ErrorAction SilentlyContinue) {
    if (Confirm-YesNo "Run 'nmap -sV --top-ports 1000 127.0.0.1' to confirm services?") {
        $nm = Join-Path $Script:OutputDir ("nmap-localhost-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
        & nmap -sV -sC -T4 --top-ports 1000 127.0.0.1 -oA $nm | Tee-Object -Variable nmout | Out-Null
        Write-Log "nmap -> $nm.*"
    }
}

Write-Host "`nMap complete. Next: option 7 (Recommendations) for the punch list." -ForegroundColor Yellow
Pause-Toolkit
