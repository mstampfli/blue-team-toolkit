# Read facts.json and emit a prioritized punch list.
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$factsPath = Join-Path $Script:OutputDir 'facts.json'
if (-not (Test-Path $factsPath)) {
    Write-Host "No facts.json yet. Run option 6 (Map) first." -ForegroundColor Yellow
    Pause-Toolkit; return
}

$facts = Get-Content $factsPath -Raw | ConvertFrom-Json
$out   = Join-Path $Script:OutputDir ("recommendations-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmm'))

$p0 = New-Object Collections.Generic.List[string]
$p1 = New-Object Collections.Generic.List[string]
$p2 = New-Object Collections.Generic.List[string]
$ok = New-Object Collections.Generic.List[string]
$tools_have = @()
$tools_miss = @()

$ss   = $facts.security_state
$role = $facts.role

# ---- P0 ----
if ($ss.smb1_state -eq 'Enabled') { $p0.Add("SMBv1 ENABLED — disable immediately (EternalBlue family) [harden step 2]") } else { $ok.Add("SMBv1 disabled") }
if ($role.is_dc -and $role.print_spooler) { $p0.Add("This is a DC AND Print Spooler is RUNNING — PrintNightmare risk, stop+disable Spooler [harden step 5]") }
if ($ss.lsa_protection_runasppl -ne 1) { $p0.Add("LSA Protection (RunAsPPL) NOT set — Mimikatz can read LSASS [harden step 1]") } else { $ok.Add("LSA Protection on") }
if ($ss.defender_realtime -eq $false) { $p0.Add("Windows Defender real-time monitoring is OFF") } else { $ok.Add("Defender real-time on") }

# ---- P1 ----
if ($ss.smb_signing_required -ne $true) { $p1.Add("SMB signing not required (server) — enable to defeat NTLM relay [harden step 3]") } else { $ok.Add("SMB signing required") }
if ($ss.smb3_compression_disabled -ne 1) { $p1.Add("SMBv3 compression NOT disabled — SMBGhost (CVE-2020-0796) workaround missing [harden step 4]") }
if ($ss.llmnr_disabled -ne $true) { $p1.Add("LLMNR is enabled — disable via DNSClient policy [harden step 6]") } else { $ok.Add("LLMNR disabled") }
if ($ss.wpad_running)    { $p1.Add("WPAD service (WinHttpAutoProxySvc) is running — stop+disable [harden step 8]") }
if ($ss.lm_compat_level -ne 5) { $p1.Add("LmCompatibilityLevel != 5 — enforce NTLMv2-only [harden step 9]") } else { $ok.Add("NTLMv2-only enforced") }
if ($ss.ps_scriptblock_logging -ne $true) { $p1.Add("PowerShell ScriptBlockLogging OFF — enable [harden step 10]") } else { $ok.Add("PS ScriptBlock logging on") }
if ($ss.ps_module_logging -ne $true)      { $p1.Add("PowerShell ModuleLogging OFF — enable [harden step 11]") }
if ($ss.sysmon_running -ne $true) {
    $p1.Add("Sysmon NOT running — install via option 1, then deploy SwiftOnSecurity config")
} else { $ok.Add("Sysmon running") }
if ($ss.credential_guard_running -ne $true -and $facts.os.product -match 'Windows (10|11|Server (2019|2022|2025))') {
    $p1.Add("Credential Guard not running on a supported OS — enable via VBS")
}

# ---- P2 ----
if (-not $facts.baselines.runkeys)  { $p2.Add("No persistence baseline (run keys) — capture via Hardening 'Snapshot persistence baseline' step") }
if (-not $facts.baselines.services) { $p2.Add("No services baseline") }

# ---- Role-driven ----
if ($role.exchange) {
    $p0.Add("Exchange detected — patch ProxyShell/ProxyNotShell, hunt webshells in OWA/auth and ECP/auth")
    if ($facts.tools_present -notcontains 'nuclei') { $tools_miss += 'nuclei (run against OWA URL)' }
}
if ($role.iis_running) {
    $p1.Add("IIS running — sweep wwwroot for recent .aspx/.dll, install request filtering rules for known attack URIs")
}
if ($role.adcs) {
    $p1.Add("AD CS detected — audit cert templates with Certify.exe (CVE-2022-26923 / ESC1-8 paths)")
}
if ($role.is_dc) {
    if ($facts.tools_present -notcontains 'sharphound') { $tools_miss += 'SharpHound (collect for BloodHound)' }
    $p0.Add("This is a DC — confirm krbtgt has been reset 2x with 1h+ gap (CyLG kill chain step 6 mitigation)")
    $p1.Add("DC — empty Backup Operators group, audit DCSync rights via BloodHound")
}
if ($role.rdp_listening) {
    $p2.Add("RDP listening (3389) — restrict via firewall to mgmt VLAN, enable NLA, consider port change")
}
if ($role.winrm_listening) {
    $p2.Add("WinRM listening (5985/5986) — confirm scoped via TrustedHosts + IP allowlist")
}

# ---- Tools availability ----
$critical = 'velociraptor','sysmon','sysmon-config','autoruns','sharphound','chainsaw','loki','nuclei','sigma','winpeas','pesieve'
foreach ($t in $critical) {
    if ($facts.tools_present -contains $t) { $tools_have += $t } else { $tools_miss += $t }
}

# Exposure surfacing (from map's $facts.exposure)
$exp = $facts.exposure
if ($exp) {
    if ($exp.ports_bound_all_interfaces -gt 0) {
        $p1.Add("$($exp.ports_bound_all_interfaces) port(s) bound to 0.0.0.0 -- review with Get-NetTCPConnection -State Listen | ? LocalAddress -in '0.0.0.0','::'")
    }
    if ($exp.services_localsystem_outside_standard_paths -gt 0) {
        $p1.Add("$($exp.services_localsystem_outside_standard_paths) LocalSystem service(s) running from non-standard paths -- candidate masquerades")
    }
    if ($exp.firewall_profiles_enabled -lt 3) {
        $p0.Add("Only $($exp.firewall_profiles_enabled)/3 Windows Firewall profiles enabled -- enable Domain+Private+Public")
    }
    if ($exp.firewall_inbound_allow_any_rules -gt 0) {
        $p2.Add("$($exp.firewall_inbound_allow_any_rules) inbound firewall rule(s) allow from RemoteAddress=Any -- audit for over-permissive scope")
    }
}

# Risky port flags
$risky = @(21,23,135,139,445,1433,1434,3306,5432,5985,5986,9200,11211,27017)
$exposed = $facts.listening_ports | Where-Object { $_ -in $risky }
if ($exposed) {
    $p1.Add("Risky port(s) listening: $($exposed -join ',') — confirm bound to internal interfaces, segmented from workstations")
}

# ---- Render ----
$lines = @()
$lines += "============================================================"
$lines += " HARDENING PUNCH LIST -- $($facts.host)"
$lines += " Generated: $(Get-Date)"
$lines += "============================================================"
$lines += ""
$lines += "OS: $($facts.os.product) build $($facts.os.build) ($($facts.os.arch))"
$lines += "Domain: $($facts.role.domain)  |  joined=$($facts.role.ad_joined)  |  is_dc=$($facts.role.is_dc)"
$lines += ""

$lines += "Detected role highlights:"
foreach ($k in 'iis_running','exchange','adcs','sql_server','rdp_listening','winrm_listening','print_spooler','hyperv','veeam') {
    $v = $role.$k
    if ($v -eq $true) { $lines += "  - $k" }
}
$lines += ""

if ($p0.Count) {
    $lines += "*** P0 -- DO NOW ***********************************************"
    $p0 | ForEach-Object { $lines += "  [!] $_" }
    $lines += ""
}
if ($p1.Count) {
    $lines += "*** P1 -- Before attack starts *********************************"
    $p1 | ForEach-Object { $lines += "  [ ] $_" }
    $lines += ""
}
if ($p2.Count) {
    $lines += "*** P2 -- If time allows ***************************************"
    $p2 | ForEach-Object { $lines += "  [ ] $_" }
    $lines += ""
}
if ($ok.Count) {
    $lines += "+++ Already in good shape ++++++++++++++++++++++++++++++++++++++"
    $ok | ForEach-Object { $lines += "  [OK] $_" }
    $lines += ""
}

$lines += "TOOLS PRESENT:"
if ($tools_have)  { $tools_have | Sort-Object -Unique | ForEach-Object { $lines += "  + $_" } } else { $lines += "  (none of the critical set installed)" }
$lines += ""
$lines += "TOOLS MISSING (install via option 1):"
if ($tools_miss)  { $tools_miss | Sort-Object -Unique | ForEach-Object { $lines += "  - $_" } } else { $lines += "  (all critical tools present)" }
$lines += ""
$lines += "Listening ports: $($facts.listening_ports -join ', ')"
$lines += ""
$lines += "Next: option 3 to walk the hardening checklist (dry-run by default)."

$lines | Tee-Object -FilePath $out
Write-Log "RECOMMEND -> $out"
Write-Host ""
Pause-Toolkit
